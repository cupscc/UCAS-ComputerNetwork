#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include <stdio.h>
#include <stdlib.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	// fprintf(stderr, "TODO: malloc and send icmp packet.\n");
	struct ether_header *e_header = (struct ether_header *)in_pkt;
	struct iphdr *ip_header = packet_to_ip_hdr(in_pkt);
	char *ip_data = IP_DATA(ip_header);
	int send_length;
	char *send_packet;
	switch (type)
	{
	case ICMP_ECHOREQUEST: // icmp request useless
		printf("receive a icmp request packet!!\n");
		exit(0);
		break;
	case ICMP_ECHOREPLY:
		send_length = ETHER_HDR_SIZE + IP_HDR_SIZE(ip_header) + len;
		send_packet = malloc(send_length);
		struct ether_header *eh = (struct ether_header *)send_packet;
		eh->ether_type = htons(ETH_P_IP);
		memcmp(eh->ether_dhost, e_header->ether_shost, ETH_ALEN);
		memcmp(eh->ether_shost, e_header->ether_dhost, ETH_ALEN);
		struct iphdr *ip_header_send = packet_to_ip_hdr(send_packet);
		rt_entry_t *src_entry = longest_prefix_match(ntohl(ip_header->saddr));
		ip_init_hdr(ip_header_send, src_entry->iface->ip, ntohl(ip_header->saddr), (IP_HDR_SIZE(ip_header) + len), IPPROTO_ICMP);
		if (code == ICMP_ECHOREPLY)
		{
			struct icmphdr *icmp_header = (struct icmphdr *)(IP_DATA(ip_header_send));
			memcpy(icmp_header, (in_pkt + ETHER_HDR_SIZE + IP_HDR_SIZE(ip_header)), len);
			icmp_header->type = ICMP_ECHOREPLY;
			icmp_header->code = ICMP_ECHOREPLY;
			icmp_header->checksum = icmp_checksum(icmp_header, len);
		}
		else
		{
			exit(0);
		}
		break;
	case ICMP_DEST_UNREACH:
		send_length = ETHER_HDR_SIZE + IP_HDR_SIZE(ip_header) + ICMP_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_COPIED_DATA_LEN;
		send_packet = malloc(send_length);
		struct ether_header *eh = (struct ether_header *)send_packet;
		eh->ether_type = htons(ETH_P_IP);
		memcmp(eh->ether_dhost, e_header->ether_shost, ETH_ALEN);
		memcmp(eh->ether_shost, e_header->ether_dhost, ETH_ALEN);
		struct iphdr *ip_header_send = packet_to_ip_hdr(send_packet);
		rt_entry_t *src_entry = longest_prefix_match(ntohl(ip_header->saddr));
		ip_init_hdr(ip_header_send, src_entry->iface->ip, ntohl(ip_header->saddr), (IP_HDR_SIZE(ip_header) + len), IPPROTO_ICMP);
		struct icmphdr *icmp_header = (struct icmphdr *)(IP_DATA(ip_header_send));
		if (code == ICMP_NET_UNREACH) // icmp router find fail
		{
			icmp_header->code = ICMP_NET_UNREACH;
		}
		else if (code == ICMP_HOST_UNREACH) // arp find fail
		{
			icmp_header->code = ICMP_HOST_UNREACH;
		}
		else
		{
			exit(0);
		}
		icmp_header->type = ICMP_DEST_UNREACH;
		memset((char *)icmp_header + 4, 0, 4);
		memcmp((char *)icmp_header + 8, (char *)ip_header, IP_HDR_SIZE(ip_header) + ICMP_COPIED_DATA_LEN);
		icmp_header->checksum = icmp_checksum(icmp_header, send_length - ETHER_HDR_SIZE - IP_HDR_SIZE(ip_header));
		break;
	case ICMP_TIME_EXCEEDED: // ttl is 0
		send_length = ETHER_HDR_SIZE + IP_HDR_SIZE(ip_header) + ICMP_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_COPIED_DATA_LEN;
		send_packet = malloc(send_length);
		struct ether_header *eh = (struct ether_header *)send_packet;
		eh->ether_type = htons(ETH_P_IP);
		memcmp(eh->ether_dhost, e_header->ether_shost, ETH_ALEN);
		memcmp(eh->ether_shost, e_header->ether_dhost, ETH_ALEN);
		struct iphdr *ip_header_send = packet_to_ip_hdr(send_packet);
		rt_entry_t *src_entry = longest_prefix_match(ntohl(ip_header->saddr));
		ip_init_hdr(ip_header_send, src_entry->iface->ip, ntohl(ip_header->saddr), (IP_HDR_SIZE(ip_header) + len), IPPROTO_ICMP);
		struct icmphdr *icmp_header = (struct icmphdr *)(IP_DATA(ip_header_send));
		if (code == ICMP_EXC_TTL)
		{
			icmp_header->type = ICMP_TIME_EXCEEDED;
			icmp_header->code = ICMP_EXC_TTL;
		}
		else
		{
			exit(0);
		}
		memset((char *)icmp_header + 4, 0, 4);
		memcmp((char *)icmp_header + 8, (char *)ip_header, IP_HDR_SIZE(ip_header) + ICMP_COPIED_DATA_LEN);
		icmp_header->checksum = icmp_checksum(icmp_header, send_length - ETHER_HDR_SIZE - IP_HDR_SIZE(ip_header));
		break;
	}
	ip_send_packet(send_packet, send_length);
	free(send_packet);
}