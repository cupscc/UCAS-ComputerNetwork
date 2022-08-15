#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static struct nat_table nat;

// get the interface from iface name
static iface_info_t *if_name_to_iface(const char *if_name)
{
	char *name_end = if_name;
	while (*name_end != ' ' && *name_end != '\n' && *name_end != '\0')
		name_end++;
	*name_end = '\0';
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list)
	{
		if (strcmp(iface->name, if_name) == 0)
			return iface;
	}

	// log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
	return NULL;
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
	// fprintf(stdout, "TODO: determine the direction of this packet.\n");
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	u32 saddr = ntohl(ip->saddr);
	u32 daddr = ntohl(ip->daddr);
	// log(DEBUG, "forwar_ip " IP_FMT "  -> " IP_FMT " \n", HOST_IP_FMT_STR(saddr), HOST_IP_FMT_STR(daddr));

	rt_entry_t *src_entry = longest_prefix_match(saddr);
	rt_entry_t *des_entry = longest_prefix_match(daddr);
	int src_internal = (src_entry->iface == nat.internal_iface);
	int des_internal = (des_entry->iface == nat.internal_iface);
	int des_external = (daddr == nat.external_iface->ip);
	// log(DEBUG, "src_entry.iface: %s , des_entry.iface: %s ", src_entry->iface->ip_str, des_entry->iface->ip_str);
	if (src_internal && !des_internal)
		return DIR_OUT;
	if (!src_internal && des_external)
		return DIR_IN;
	return DIR_INVALID;
}
u8 hash_rmt(u32 remote_ip, u16 remote_port)
{
	char tmp[6];
	memcpy(&tmp[0], (char *)&remote_ip, 4);
	memcpy(&tmp[4], (char *)&remote_port, 2);
	return hash8(tmp, 6);
}
u16 assign_external_port(void)
{
	for (u16 i = NAT_PORT_MIN; i < NAT_PORT_MAX; i++)
	{
		if (nat.assigned_ports[i] == 0)
		{
			nat.assigned_ports[i] = 1;
			return i;
		}
	}

	// log(ERROR, "there is no more external port\n");
	return 0;
}
struct nat_mapping *nat_look_up(struct iphdr *ip, struct tcphdr *tcp, int dir)
{
	u32 rmt_ip, int_ip, ext_ip;
	u16 rmt_port, int_port, ext_port;
	struct nat_mapping *entry = NULL;
	// printf("dir2: %d\n", dir);

	if (dir == DIR_IN)
	{
		rmt_ip = ntohl(ip->saddr);
		rmt_port = ntohs(tcp->sport);
		ext_ip = ntohl(ip->daddr);
		ext_port = ntohs(tcp->dport);
		u8 index = hash_rmt(rmt_ip, rmt_port);
		list_for_each_entry(entry, &nat.nat_mapping_list[index], list)
		{
			if (entry->external_ip == ext_ip && entry->external_port == ext_port)
				return entry;
		}
	}

	if (dir == DIR_OUT)
	{
		rmt_ip = ntohl(ip->daddr);
		rmt_port = ntohs(tcp->dport);
		int_ip = ntohl(ip->saddr);
		int_port = ntohs(tcp->sport);
		// log(DEBUG, "rmt  " IP_FMT "  -> " IP_FMT " \n", HOST_IP_FMT_STR(int_ip), HOST_IP_FMT_STR(rmt_ip));
		u8 index = hash_rmt(rmt_ip, rmt_port);
		list_for_each_entry(entry, &(nat.nat_mapping_list[index]), list)
		{
			if (entry->internal_ip == int_ip && entry->internal_port == int_port)
			{
				return entry;
			}
		}
	}
	return NULL;
}
// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection

struct nat_mapping *new_map_entry(u32 rmt_ip, u16 rmt_port, u32 int_ip, u16 int_port, u32 ext_ip, u16 ext_port)
{
	struct nat_mapping *map_entry = (struct nat_mapping *)malloc(sizeof(struct nat_mapping));
	map_entry->remote_ip = rmt_ip;
	map_entry->remote_port = rmt_port;
	map_entry->internal_ip = int_ip;
	map_entry->internal_port = int_port;
	map_entry->external_ip = ext_ip;
	map_entry->external_port = ext_port;
	map_entry->update_time = time(NULL);

	map_entry->conn.internal_fin = 0;
	map_entry->conn.external_fin = 0;
	map_entry->conn.internal_seq_end = 0;
	map_entry->conn.external_seq_end = 0;
	map_entry->conn.internal_ack = 0;
	map_entry->conn.external_ack = 0;
	init_list_head(&map_entry->list);
	list_add_tail(&map_entry->list, &(nat.nat_mapping_list[hash_rmt(rmt_ip, rmt_port)]));
	return map_entry;
}
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
	// fprintf(stdout, "TODO: do translation for this packet.\n");
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = packet_to_tcp_hdr(packet);
	pthread_mutex_lock(&nat.lock);
	// printf("dir: %d\n", dir);
	struct nat_mapping *entry = nat_look_up(ip, tcp, dir);
	if (entry != NULL)
	{
		// log(DEBUG, "we have find it: " IP_FMT " %d -> " IP_FMT " %d\n", HOST_IP_FMT_STR(entry->internal_ip), entry->internal_port, HOST_IP_FMT_STR(entry->external_ip), entry->external_port);
	}
	if (entry == NULL)
	{
		if (dir == DIR_OUT && tcp->flags == TCP_SYN)
		{
			u16 ext_port = assign_external_port();
			entry = new_map_entry(ntohl(ip->daddr), ntohs(tcp->dport), ntohl(ip->saddr), ntohs(tcp->sport), nat.external_iface->ip, ext_port);
			u32 ip_src = ntohl(ip->saddr);
			// log(DEBUG, "snat new mapping: " IP_FMT " %d -> " IP_FMT " %d\n", HOST_IP_FMT_STR(ip_src), ntohs(tcp->sport), HOST_IP_FMT_STR(nat.external_iface->ip), ext_port);
		}
		if (dir == DIR_IN && tcp->flags == TCP_SYN)
		{
			struct dnat_rule *rule_entry = NULL;
			list_for_each_entry(rule_entry, &nat.rules, list)
			{
				if (rule_entry->external_ip == ntohl(ip->daddr) && rule_entry->external_port == ntohs(tcp->dport))
				{
					entry = new_map_entry(ntohl(ip->saddr), ntohs(tcp->sport), rule_entry->internal_ip, rule_entry->internal_port, rule_entry->external_ip, rule_entry->external_port);
					// log(DEBUG, "dnat new mapping: " IP_FMT " %d -> " IP_FMT " %d\n", HOST_IP_FMT_STR(rule_entry->internal_ip), rule_entry->internal_port, HOST_IP_FMT_STR(rule_entry->external_ip), rule_entry->external_port);
					break;
				}
			}
		}
	}
	if (entry == NULL)
	{
		// log(ERROR, "can not find or build mapping\n");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		pthread_mutex_unlock(&nat.lock);
		return;
	}
	if (dir == DIR_IN)
	{
		// log(DEBUG, "handle in tcp packet\n");
		int clear = (tcp->flags & TCP_RST) ? 1 : 0;
		entry->conn.external_fin = (tcp->flags & TCP_FIN) ? 1 : 0;
		entry->conn.external_seq_end = tcp_seq_end(ip, tcp);
		entry->conn.external_ack = ntohl(tcp->ack);
		entry->update_time = time(NULL);

		tcp->dport = htons(entry->internal_port);
		ip->daddr = htonl(entry->internal_ip);
		tcp->checksum = tcp_checksum(ip, tcp);
		ip->checksum = ip_checksum(ip);

		rt_entry_t *rt_dest = longest_prefix_match(entry->internal_ip);
		if (!rt_dest)
		{
			// log(ERROR, "can not find the route to dest ip\n");
			icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
			free(packet);
			pthread_mutex_unlock(&nat.lock);
			return;
		}

		if (rt_dest->gw == 0)
		{
			iface_send_packet_by_arp(nat.internal_iface, entry->internal_ip, packet, len);
		}
		else
		{
			iface_send_packet_by_arp(nat.internal_iface, rt_dest->gw, packet, len);
		}

		if (clear)
		{
			nat.assigned_ports[entry->external_port] = 0;
			list_delete_entry(&(entry->list));
			free(entry);
		}
	}
	else if (dir == DIR_OUT)
	{
		// log(DEBUG, "handle out tcp packet\n");
		int clear = (tcp->flags & TCP_RST) ? 1 : 0;
		entry->conn.internal_fin = (tcp->flags & TCP_FIN) ? 1 : 0;
		entry->conn.internal_seq_end = tcp_seq_end(ip, tcp);
		entry->conn.internal_ack = ntohl(tcp->ack);
		entry->update_time = time(NULL);

		tcp->sport = htons(entry->external_port);
		ip->saddr = htonl(entry->external_ip);
		tcp->checksum = tcp_checksum(ip, tcp);
		ip->checksum = ip_checksum(ip);

		rt_entry_t *rt_dest = longest_prefix_match(entry->remote_ip);
		if (!rt_dest)
		{
			// log(ERROR, "can not find the route to dest ip\n");
			free(packet);
			pthread_mutex_unlock(&nat.lock);
			return;
		}

		if (rt_dest->gw == 0)
		{
			iface_send_packet_by_arp(nat.external_iface, entry->remote_ip, packet, len);
		}
		else
		{
			iface_send_packet_by_arp(nat.external_iface, rt_dest->gw, packet, len);
		}

		if (clear)
		{
			nat.assigned_ports[entry->external_port] = 0;
			list_delete_entry(&(entry->list));
			free(entry);
		}
	}

	pthread_mutex_unlock(&nat.lock);
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	int dir = get_packet_direction(packet);
	if (dir == DIR_INVALID)
	{
		// log(ERROR, "invalid packet direction, drop it.");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->protocol != IPPROTO_TCP)
	{
		// log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
		free(packet);
		return;
	}

	do_translation(iface, packet, len, dir);
}

// check whether the flow is finished according to FIN bit and sequence number
// XXX: seq_end is calculated by `tcp_seq_end` in tcp.h
static int is_flow_finished(struct nat_connection *conn)
{
	return (conn->internal_fin && conn->external_fin) &&
		   (conn->internal_ack >= conn->external_seq_end) &&
		   (conn->external_ack >= conn->internal_seq_end);
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout()
{
	while (1)
	{
		// fprintf(stdout, "TODO: sweep finished flows periodically.\n");
		sleep(1);
		pthread_mutex_lock(&nat.lock);
		for (int i = 0; i < HASH_8BITS; i++)
		{
			struct nat_mapping *mapping = NULL, *mapping_q = NULL;
			list_for_each_entry_safe(mapping, mapping_q, &nat.nat_mapping_list[i], list)
			{
				if (time(NULL) - mapping->update_time >= TCP_ESTABLISHED_TIMEOUT || is_flow_finished(&mapping->conn))
				{
					// log(INFO, "remove map entry, port: %d\n", mapping->external_port);
					nat.assigned_ports[mapping->external_port] = 0;
					list_delete_entry(&mapping->list);
					free(mapping);
				}
			}
		}
		pthread_mutex_unlock(&nat.lock);
	}

	return NULL;
}

// u32 ipv4_to_uint(const char *p)
// {
// 	int ip_lengtn = 16;
// 	char ip[ip_lengtn];
// 	memset(ip, 0, ip_lengtn);
// 	for (int i = 0; p[0] != ':' && i < ip_lengtn; p++, i++)
// 	{
// 		ip[i] = p[0];
// 	}
// 	printf("%s\n", ip);
// 	u32 res = inet_addr(ip);
// 	// free(ip);
// }//这里为啥不能free 不能free这个空间吗
u32 ipv4_to_uint(char *ipv4) //这个做法值得学习
{
	u32 sum = 0;
	for (int i = 1; i <= 4; i++)
	{
		sum = sum * 256 + atoi(ipv4);
		while (*ipv4 >= '0' && *ipv4 <= '9')
			ipv4++;
		ipv4++;
	}
	return sum;
}
int parse_config(const char *filename)
{
	FILE *fp = fopen(filename, "r"); //?
	char *line = (char *)malloc(100);
	memset(line, 0, 100);
	if (fp == NULL)
	{
		perror("this file does not exist\n");
		return -1;
	}
	while (fgets(line, 100, fp))
	{
		char *internal;
		if ((internal = strstr(line, "internal-iface: ")) != NULL)
		{
			internal += strlen("internal-iface: ");
			nat.internal_iface = if_name_to_iface(internal);
			// log(DEBUG, "internal_iface: " IP_FMT "\n", HOST_IP_FMT_STR(nat.internal_iface->ip));
			continue;
		}
		char *external;
		if ((external = strstr(line, "external-iface: ")) != NULL)
		{
			external += strlen("external-iface: ");
			nat.external_iface = if_name_to_iface(external);
			// log(DEBUG, "external_iface: " IP_FMT "\n", HOST_IP_FMT_STR(nat.external_iface->ip));
			continue;
		}
		char *drule;
		if ((drule = strstr(line, "dnat-rules: ")) != NULL)
		{
			struct dnat_rule *new_rule = (struct dnat_rule *)malloc(sizeof(struct dnat_rule));
			memset(new_rule, 0, sizeof(new_rule));
			init_list_head(&new_rule->list);
			//("hello\n");
			drule += strlen("dnat-rules: ");
			// printf("1:%s\n", drule);
			new_rule->external_ip = ipv4_to_uint(drule); //本来企图使用inet_addr
			drule = strstr(drule, ":");
			drule += 1;
			// printf("2:%s\n", drule);
			new_rule->external_port = atoi(drule);
			drule = strstr(drule, "->");
			drule += 3;
			// printf("3:%s\n", drule);
			new_rule->internal_ip = ipv4_to_uint(drule);
			drule = strstr(drule, ":"); //不能直接加 你自己不看返回值
			drule += 1;
			// printf("4:%s\n", drule);
			new_rule->internal_port = atoi(drule);
			list_add_tail(&new_rule->list, &nat.rules);
			nat.assigned_ports[new_rule->external_port] = 1;
			// log(DEBUG, "dnat_rule: " IP_FMT " %d " IP_FMT " %d\n", HOST_IP_FMT_STR(new_rule->external_ip),new_rule->external_port, HOST_IP_FMT_STR(new_rule->internal_ip), new_rule->internal_port);
			continue;
		}
	}
	fclose(fp);
	free(line);
	return 0;
}

// initialize
void nat_init(const char *config_file)
{
	memset(&nat, 0, sizeof(nat));

	for (int i = 0; i < HASH_8BITS; i++)
		init_list_head(&nat.nat_mapping_list[i]);

	init_list_head(&nat.rules);

	// seems unnecessary
	memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));
	parse_config(config_file);

	pthread_mutex_init(&nat.lock, NULL);

	pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

void nat_exit()
{
	// fprintf(stdout, "TODO: release all resources allocated.\n");
	for (int i = 0; i < HASH_8BITS; i++)
	{
		struct nat_mapping *map_entry = NULL, *map_q = NULL;
		list_for_each_entry_safe(map_entry, map_q, &nat.nat_mapping_list[i], list)
		{
			list_delete_entry(&map_entry->list);
			free(map_entry);
		}
	}
	struct dnat_rule *rule = NULL, *rule_p = NULL;
	list_for_each_entry_safe(rule, rule_p, &nat.rules, list)
	{
		list_delete_entry(&rule->list);
		free(rule);
	}
}
