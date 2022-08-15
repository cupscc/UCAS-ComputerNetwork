#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include <stdio.h>
#include <unistd.h>

static struct list_head timer_list;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	//	fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	struct tcp_timer *timer_entry = NULL, *time_q = NULL;
	list_for_each_entry_safe(timer_entry, time_q, &timer_list, list)
	{
		if (timer_entry->enable == 1 && timer_entry->type == 0 && ((time(NULL) - timer_entry->timeout) > TCP_TIMEWAIT_TIMEOUT / 1000000))
		{
			struct tcp_sock *tsk = timewait_to_tcp_sock(timer_entry);
			list_delete_entry(&timer_entry->list);
			tcp_set_state(tsk, TCP_CLOSED);
			tcp_unhash(tsk);
			tcp_bind_unhash(tsk);
		}
	}
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	tsk->timewait.type = 0;
	tsk->timewait.enable = 1;
	tsk->timewait.timeout = time(NULL);
	list_add_tail(&tsk->timewait.list, &timer_list);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	while (1)
	{
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}
