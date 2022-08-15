#include "base.h"
#include <stdio.h>

// XXX ifaces are stored in instace->iface_list
extern ustack_t *instance;

extern void iface_send_packet(iface_info_t *iface, const char *packet, int len);

void broadcast_packet(iface_info_t *iface, const char *packet, int len)
{
	// TODO: broadcast packet
	// fprintf(stdout, "TODO: broadcast packet.\n");
	iface_info_t *iface_pos = NULL;
	list_for_each_entry(iface_pos, &instance->iface_list, list)
	{
		if (iface_pos->fd == iface->fd)
		{
			continue;
		}
		iface_send_packet(iface_pos, packet, len);
	}
}
