#include "base.h"
#include <stdio.h>

extern ustack_t *instance;

// the memory of ``packet'' will be free'd in handle_packet().
void broadcast_packet(iface_info_t *iface, const char *packet, int len)
{
	// TODO: broadcast packet
	// fprintf(stdout, "broadcast packet.\n");
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
