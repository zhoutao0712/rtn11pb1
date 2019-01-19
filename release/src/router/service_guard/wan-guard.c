
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <stdint.h>
#include <syslog.h>
#include <ctype.h>

#include <bcmnvram.h>
#include <shutils.h>
#include <shared.h>

#include <event2/dns.h>
#include <event2/util.h>
#include <event2/event.h>

#include <sys/socket.h>

#include <assert.h>

struct resolv_share_data {
	struct event_base *base;
	struct evdns_base *dnsbase;
	int n;
	int fail_count;
};

struct user_data {
	char *name; /* the name we're resolving */
	int idx; /* its position on the command line */

	struct resolv_share_data *s;
};

static void callback(int errcode, struct evutil_addrinfo *addr, void *ptr)
{
	struct user_data *data = ptr;
	const char *name = data->name;
	if (errcode) {
		printf("%d. %s -> %s\n", data->idx, name, evutil_gai_strerror(errcode));
		data->s->fail_count++;
	} else {
		struct evutil_addrinfo *ai;

		printf("%d. %s", data->idx, name);
		if (addr->ai_canonname) printf(" [%s]", addr->ai_canonname);
		puts("");

		for (ai = addr; ai; ai = ai->ai_next) {
			char buf[128];
			const char *s = NULL;
			if (ai->ai_family == AF_INET) {
				struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
				s = evutil_inet_ntop(AF_INET, &sin->sin_addr, buf, 128);
			} else if (ai->ai_family == AF_INET6) {
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->ai_addr;
				s = evutil_inet_ntop(AF_INET6, &sin6->sin6_addr, buf, 128);
			}
			if (s) printf("    -> %s\n", s);
		}

		data->s->n++;
		evutil_freeaddrinfo(addr);
	}

	if((data->s->n) || (data->s->fail_count == 3)) event_base_loopbreak(data->s->base);
}

static int check_dns(void)
{
	int i;
	struct resolv_share_data share;

	struct user_data user[3] = {
		{
			.name = "www.baidu.com",
			.idx = 1,
			.s = &share,
		},
		{
			.name = "www.qq.com",
			.idx = 2,
			.s = &share,
		},
		{
			.name = "www.taobao.com",
			.idx = 3,
			.s = &share,
		}
	};

	share.n = 0;
	share.fail_count = 0;

	share.base = event_base_new();
	if (!share.base) return 1;

	share.dnsbase = evdns_base_new(share.base, 1);
	if (!share.dnsbase) return 2;

	evdns_base_set_option(share.dnsbase, "timeout", "10.0");
	evdns_base_set_option(share.dnsbase, "max-timeouts", "3");

	for (i = 0; i < 3; ++i) {
		struct evutil_addrinfo hints;
		struct evdns_getaddrinfo_request *req;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;				// only ipv4
		hints.ai_flags = EVUTIL_AI_CANONNAME;

		req = evdns_getaddrinfo(
			share.dnsbase, user[i].name, NULL /* no service name given */,
			&hints, callback, &user[i]
		);
		if (req == NULL) {
			printf("    [request for %s returned immediately]\n", user[i].name);
		}
	}

	event_base_dispatch(share.base);

	evdns_base_free(share.dnsbase, 0);
	event_base_free(share.base);

	if(share.n) return 0;

	return 3;
}

int main(int argc, char **argv)
{
	signal(SIGPIPE, SIG_IGN);
	signal(SIGALRM, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGCHLD, chld_reap);

	if(argc == 1) {
		if (daemon(1, 1) == -1) {
			syslog(LOG_ERR, "daemon: %m");
			return 0;
		}
	}

	sleep(60);
	while(1) {
		sleep(60);
		if(check_dns() != 0) {
			sleep(5);
			if(check_dns() != 0) {
				eval("service", "restart_wan");
				sleep(30);
			}
		}
	}

	return 0;
}

