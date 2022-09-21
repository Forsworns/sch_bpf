#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define PFIFO_LIMIT 1000

// refer `skb_map_alloc_check` for bpf_attr sanity
struct {
	__uint(type, BPF_MAP_TYPE_SKBMAP);
	__type(key, __u64);
	__uint(max_entries, PFIFO_LIMIT);
} pfifo_map SEC(".maps");

SEC("sch_bpf/enqueue")
int _enqueue_pfifo(struct sch_bpf_ctx *ctx)
{
	// the patch is not complete, the verifier reuses the tc_cls_act_verifier_ops,
	// so we have to lie to the verifier
	// carry ops on skb
	int ret = bpf_skb_map_push(&pfifo_map, ctx->skb, 0);
	if (ret < 0) {
		return SCH_BPF_DROP;
	}
	return SCH_BPF_QUEUED;
}

SEC("sch_bpf/dequeue")
int _dequeue_pfifo(struct sch_bpf_ctx *ctx)
{
	unsigned long ret = bpf_skb_map_pop(&pfifo_map, 0);
	if (ret == 0) {
		return ret;
	}
	ctx->skb = (struct sk_buff *) ret;
	return SCH_BPF_DEQUEUED;
}

char _license[] SEC("license") = "GPL";
