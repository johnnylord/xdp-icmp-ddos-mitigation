/* SPDX-License-Identifier: GPL-2.0 */

/* Used *ONLY* by BPF-prog running kernel side. */
#ifndef __XDP_STATS_KERN_H
#define __XDP_STATS_KERN_H

/* Data record type 'struct datarec' is defined in common/xdp_stats_kern_user.h,
 * programs using this header must first include that file.
 */
#ifndef __XDP_STATS_KERN_USER_H
#warning "You forgot to #include <common/xdp_stats_kern_user.h>"
#include <common/xdp_stats_kern_user.h>
#endif

/* Keeps stats per (enum) xdp_action */
struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

struct bpf_map_def SEC("maps") xdp_icmp_suspect_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct profile),
	.max_entries = XDP_SUSPECT_MAX,
};

static __always_inline
__u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
		return XDP_ABORTED;

	/* BPF_MAP_TYPE_PERCPU_ARRAY returns a data record specific to current
	 * CPU and XDP hooks runs under Softirq, which makes it safe to update
	 * without atomic operations.
	 */
	rec->rx_packets++;
	rec->rx_bytes += (ctx->data_end - ctx->data);

	return action;
}

static __always_inline
struct profile *xdp_icmp_suspect_record(struct xdp_md *ctx, __u32 suspect)
{
    int ret;
    struct profile *profile;
    struct profile new_profile = { 0 };

	/* Lookup in kernel BPF-side return pointer to actual data record */
	profile = bpf_map_lookup_elem(&xdp_icmp_suspect_map, &suspect);
	if (!profile) {
        /* Create an element for this suspect */
        new_profile.cur_rx_packets = 1;
        new_profile.cur_rx_bytes = (ctx->data_end - ctx->data);
        new_profile.last_seen = bpf_ktime_get_ns();
        new_profile.action = XDP_PASS;
        ret = bpf_map_update_elem(&xdp_icmp_suspect_map, &suspect, &new_profile, BPF_NOEXIST);
        if (ret < 0) {
            return NULL;
        } else {
            return bpf_map_lookup_elem(&xdp_icmp_suspect_map, &suspect);
        }
    } else {
        profile->cur_rx_packets++;
        profile->cur_rx_bytes += (ctx->data_end - ctx->data);
        return profile;
    }
}

static __always_inline
void xdp_icmp_suspect_catchup(struct xdp_md *ctx, __u32 suspect)
{
    struct profile *profile;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	profile = bpf_map_lookup_elem(&xdp_icmp_suspect_map, &suspect);
	if (!profile) {
        return;
    } else {
        profile->pre_rx_packets = profile->cur_rx_packets;
        profile->pre_rx_bytes = profile->cur_rx_bytes;
        profile->last_seen = bpf_ktime_get_ns();
        return;
    }
}

#endif /* __XDP_STATS_KERN_H */
