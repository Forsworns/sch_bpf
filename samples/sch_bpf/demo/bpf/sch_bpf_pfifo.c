#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <libmnl/libmnl.h>

// the header generated from sch_bpf_pfifo.bpf.c by bpftool
#include "sch_bpf_pfifo.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vprintf(format, args);
}

// to make it fair, we directly call netlink for native pfifo qdisc
// also learn how to use netlink create qdisc :)

#define TCA_BUF_MAX (64 * 1024)
#define FILTER_NAMESZ 16

int ret = 0, portid = 0, seq = 0;
struct sch_bpf_pfifo_bpf *skel = NULL;
bool b_replace = false, b_delete = false;
unsigned int if_idx;
char ifname[IF_NAMESIZE + 1] = "lo";
unsigned int tc_hd = 0x8000000;
struct mnl_socket* nl;
const char qdisc_type[FILTER_NAMESZ] = "bpf";

static void usage(void)
{
	printf("Usage: use netlink to create bpf qdisc in net/sch [...]\n");
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
	if (!b_delete) {
		exit(0);
	}
	psignal(signo,
		"Delete the added bpf qdisc. Restore the environment. Shutting down....");
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
	req.n.nlmsg_seq = seq = time(NULL);
	if_idx = if_nametoindex(ifname);
	if (errno == ENODEV) {
		printf("Device not exists\n");
		ret = -ENODEV;
		exit(ret);
	}
	req.t.tcm_ifindex = if_idx;
	// to simplify, we only consider root qdisc here
	req.t.tcm_parent = TC_H_ROOT;
	// once qdisc is set to root, this config can be neglected,
	// otherwise, the handle has to be set
	req.t.tcm_handle = tc_hd;

	if (mnl_socket_sendto(nl, &req.n, req.n.nlmsg_len) < 0) {
		ret = -EPIPE;
		exit(ret);
	}
	exit(0);
}

static int load_bpf(void)
{
	int ret = 0;
	// set up libbpf errors and debug info callback
	libbpf_set_print(libbpf_print_fn);
	LIBBPF_OPTS(bpf_object_open_opts, opts, .kernel_log_level = 2);
	skel = sch_bpf_pfifo_bpf__open_opts(&opts);
	if (!skel) {
		printf("Fail to open the bpf skeleton");
		return EINVAL;
	}

	// load & verify BPF programs
	ret = sch_bpf_pfifo_bpf__load(skel);
	if (ret) {
		printf("Failed to load and verify BPF skeleton\n");
	}

	// attach sch_bpf handler
	ret = sch_bpf_pfifo_bpf__attach(skel);
	if (ret) {
		printf("Failed to attach BPF skeleton\n");
	}
	return -ret;
}

static int add_sch_pfifo(void)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, MNL_SOCKET_BUFFER_SIZE);
	char eq_prog_name[] = "_enqueue_pfifo";
	char dq_prog_name[] = "_dequeue_pfifo";
	int eq_prog_fd, dq_prog_fd;
	struct rtattr *option_attr;
	// init the global ebpf map for qdisc configuration
	unsigned int if_idx = if_nametoindex(ifname);
	if (errno == ENODEV) {
		printf("Device not exists\n");
		return -ENODEV;
	}
	// load bpf and get fds
	load_bpf();
	if (skel->progs._enqueue_pfifo == NULL ||
	    skel->progs._dequeue_pfifo == NULL) {
		printf("Cannot load programs");
		return -ENODEV;
	}

	eq_prog_fd = bpf_program__fd(skel->progs._enqueue_pfifo);
	dq_prog_fd = bpf_program__fd(skel->progs._dequeue_pfifo);
	printf("eq_prog_fd: %d, dq_prog_fd: %d\n", eq_prog_fd, dq_prog_fd);

	if (eq_prog_fd < 0 || dq_prog_fd < 0) {
		printf("Invalid program fd, load failed\n");
		return -EINVAL;
	}

	// use netlink to add a tc qdisc
	struct {
		struct nlmsghdr n;
		struct tcmsg t;
		char buf[TCA_BUF_MAX];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE,
		.n.nlmsg_type = RTM_NEWQDISC,
		.t.tcm_family = AF_UNSPEC,
	};
	req.t.tcm_ifindex = if_idx;
	// to simplify, we only consider root qdisc here
	req.t.tcm_parent = TC_H_ROOT;
	// once qdisc is set to root, this config can be neglected
	req.t.tcm_handle = tc_hd;
	mnl_attr_put_str(&req.n, TCA_KIND, qdisc_type);

	// the specific options for a qdisc should be set to a
	// nested TCA_OPTIONS field, though there is not an option
	// struct as defined in pfifo
	option_attr = (struct rtattr *) mnl_nlmsg_get_payload_tail(&req.n); 
	mnl_attr_put(&req.n, TCA_OPTIONS, 0, NULL);
	mnl_attr_put_u32(&req.n, TCA_SCH_BPF_ENQUEUE_PROG_FD, eq_prog_fd);
	mnl_attr_put(&req.n, TCA_SCH_BPF_ENQUEUE_PROG_NAME,strlen(dq_prog_name)+1, eq_prog_name);
	mnl_attr_put_u32(&req.n, TCA_SCH_BPF_DEQUEUE_PROG_FD, dq_prog_fd);
	mnl_attr_put(&req.n, TCA_SCH_BPF_DEQUEUE_PROG_NAME, strlen(dq_prog_name)+1,dq_prog_name);
	// update the length in the header of the nested option
	option_attr->rta_len = (void *)mnl_nlmsg_get_payload_tail(&req.n) - (void *)option_attr;
	
	if (mnl_socket_sendto(nl, &req.n, req.n.nlmsg_len) < 0) {
		return -EPIPE;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "i:q:rhd")) != -1) {
		switch (opt) {
		/* General args */
		case 'i':
			strcpy(ifname, optarg);
			break;
		case 'q':
			ret = get_qdisc_handle(&tc_hd, optarg);
			if (ret) {
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
	sch_bpf_pfifo_bpf__destroy(skel);
	return ret;
}