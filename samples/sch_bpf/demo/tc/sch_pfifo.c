#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include <libmnl/libmnl.h>

// to make it fair, we directly call netlink for native pfifo qdisc
// also learn how to use netlink create qdisc :)

#define TCA_BUF_MAX (64 * 1024)
#define FILTER_NAMESZ	16
#define PFIFO_LIMIT 1000

int ret = 0;
bool b_replace = false, b_delete = false;
char ifname[IF_NAMESIZE + 1] = "lo";
unsigned int tc_hd = 0x8000000;
struct mnl_socket* nl;
const char qdisc_type[FILTER_NAMESZ] = "pfifo";

static void usage(void)
{
	printf("Usage: use netlink to create pfifo qdisc in net/sch [...]\n");
	printf("       -i <ifindex> Interface index\n");
	printf("       -h <handle>  Qdisc handle\n");
	printf("       -d 		    Delete the qdisc before quit\n");
	printf("       -r   		Replace Qdisc if exists\n");
}

static int get_qdisc_handle(__u32 *h, const char *str)
{
	__u32 maj;
	char *p;

	maj = TC_H_UNSPEC;
	if (strcmp(str, "none") == 0)
		goto ok;
	maj = strtoul(str, &p, 16);
	if (p == str || maj >= (1 << 16))
		return -1;
	maj <<= 16;
	if (*p != ':' && *p != 0)
		return -1;
ok:
	*h = maj;
	return 0;
}

static void sigdown(int signo)
{
	if(!b_delete){
		exit(0);
	}
	psignal(signo,
		"Delete the added pfifo qdisc. Restore the environment. Shutting down....");
	// delete the added qdisc, restore the environment
	struct {
		struct nlmsghdr n;
		struct tcmsg t;
		char buf[TCA_BUF_MAX];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST,
		.n.nlmsg_type = RTM_DELQDISC,
		.t.tcm_family = AF_UNSPEC,
	};

	unsigned int if_idx = if_nametoindex(ifname);
	if (errno == ENODEV) {
		printf("Device not exists\n");
		ret = -ENODEV;
		exit(ret);
	}
	req.t.tcm_ifindex = if_idx;
	// to simplify, we only consider root qdisc here
	req.t.tcm_parent = TC_H_ROOT;

	if (mnl_socket_sendto(nl, &req.n, req.n.nlmsg_len) < 0) {
		ret = -EPIPE;
		exit(ret);
	}
	exit(0);
}

static int add_sch_pfifo(void)
{
	// use netlink to add a tc qdisc
	struct {
		struct nlmsghdr n;
		struct tcmsg t;
		char buf[TCA_BUF_MAX];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE,
		.n.nlmsg_type = RTM_NEWQDISC,
		.t.tcm_family = AF_UNSPEC,
	};
	if(b_replace){
		req.n.nlmsg_flags |= NLM_F_REPLACE;
	}else{
		req.n.nlmsg_flags |= NLM_F_EXCL;
	}
	unsigned int if_idx = if_nametoindex(ifname);
	if (errno == ENODEV) {
		printf("Device not exists\n");
		return -ENODEV;
	}
	req.t.tcm_ifindex = if_idx;
	// to simplify, we only consider root qdisc here
	req.t.tcm_parent = TC_H_ROOT;
	// once qdisc is set to root, this config can be neglected,
	// otherwise, the handle has to be set
	// req.t.tcm_handle = tc_hd;

	mnl_attr_put_str(&req.n, TCA_KIND, qdisc_type);
	// for pfifo, this is the pkt number
	struct tc_fifo_qopt opt = {};
	opt.limit = PFIFO_LIMIT;
	mnl_attr_put(&req.n, TCA_OPTIONS, sizeof(opt), &opt);
	if (mnl_socket_sendto(nl, &req.n, req.n.nlmsg_len) < 0) {
		return -EPIPE;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "i:q:rdh")) != -1) {
		switch (opt) {
		/* General args */
		case 'i':
			strcpy(ifname, optarg);
			break;
		case 'q':
			ret = get_qdisc_handle(&tc_hd, optarg);
			if (ret){
				printf("invalid qdisc handle");
				return ret;
			}
			break;
		case 'r':
			b_replace = true;
			break;
		case 'd':
			b_delete = true;
			break;
		default:
			usage();
			return 0;
		}
	}
	// take control of signals
	if (sigaction(SIGINT, &(struct sigaction){ .sa_handler = sigdown },
		      NULL)) {
		goto out;
	}
	if (sigaction(SIGTERM, &(struct sigaction){ .sa_handler = sigdown },
		      NULL)) {
		goto out;
	}

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		printf("Cannot open rtnetlink\n");
		return -ENOENT;
	}

	// add the pfifo qdisc
	// use pidstat to collect cpu/memory metric
	ret = add_sch_pfifo();
	if (ret < 0) {
		goto out;
	}

	for (;;) {
		pause();
	}

out:
	mnl_socket_close(nl);
	return ret;
}