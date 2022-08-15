#include "ip.h"
#include "icmp.h"
#include <stdio.h>
#include <stdlib.h>

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	// fprintf(stderr, "TODO: handle ip packet.\n");
	// char *ip_packet = packet + ETHER_HDR_SIZE;
	struct iphdr *ip_header = packet_to_ip_hdr(packet);
	char *ip_data = IP_DATA(ip_header);
	if (ip_header->protocol == IPPROTO_ICMP)
	{
		struct icmphdr *icmp_header = (struct icmphdr *)ip_data;
		if (icmp_header->type == ICMP_ECHOREQUEST && memcmp(ip_header->daddr, iface->ip_str) == 0)
		{
			int icmp_len = len - ETHER_HDR_SIZE - IP_HDR_SIZE(ip_header);
			icmp_send_packet(packet, icmp_len, ICMP_ECHOREPLY, ICMP_ECHOREPLY);
		}
	}
	else
	{
		longest_prefix_match
		// forward the packet
	}
}
