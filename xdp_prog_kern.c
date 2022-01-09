#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common/parsing_helpers.h"
#include "common/rewrite_helpers.h"
#include "common/xdp_stats_kern_user.h"
#include "common/xdp_stats_kern.h"

// Kernel didin't define vlaue for IPPROTO_ICMP6
#define IPPROTO_ICMP6 58
#define NANO 1000000000


SEC("xdp_icmp_dos_mitigation")
int xdp_icmp_dos_mitigation_func(struct xdp_md *ctx)
{
    /* Default response */
    int action = XDP_PASS;

    /* Setup the parsing header */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct hdr_cursor nh = { .pos = data };

    /* Layer2 (Link) */
    int eth_type;
    struct ethhdr *eth;
    /* Layer3 (Network) */
    int ip_type;
    struct iphdr *iphdr;
    struct ipv6hdr *ipv6hdr;
    /* Layer4 (Transport) */
    struct udphdr *udphdr;
    struct tcphdr *tcphdr;
    struct icmphdr *icmphdr;
    struct icmp6hdr *icmp6hdr;

    /* DDoS Mitigation */
    __u64 elapsed_time, pps;
    struct profile *target_profile;

    /* Layer2 Parsing */
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) {
        action = XDP_ABORTED;
        goto out;
    }

    /* Layer3 Parsing (IPv4 or IPv6) */
    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
    } else {
        goto out;
    }

    /* Layer4 Parsing (TCP or UDP or ICMP or ICMPv6) */
    if (ip_type == IPPROTO_UDP) {
        if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
            action = XDP_ABORTED;
            goto out;
        }
    } else if (ip_type == IPPROTO_TCP) {
        if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
            action = XDP_ABORTED;
            goto out;
        }
    } else if (ip_type == IPPROTO_ICMP && eth_type == bpf_htons(ETH_P_IP)) {
        if (parse_icmphdr(&nh, data_end, &icmphdr) < 0) {
            action = XDP_ABORTED;
            goto out;
        }
    } else if (ip_type == IPPROTO_ICMP6 && eth_type == bpf_htons(ETH_P_IPV6)) {
        if (parse_icmp6hdr(&nh, data_end, &icmp6hdr) < 0) {
            action = XDP_ABORTED;
            goto out;
        }
    } else {
        goto out;
    }

    /* Update the statistics of traffic from specific source (IPv4) */
    target_profile = xdp_icmp_suspect_record(ctx, bpf_ntohs(iphdr->saddr));
    if (!target_profile) {
        action = XDP_ABORTED;
        goto out;
    }

    /* DDoS Mitifation based on packet per second metric */
    elapsed_time = (bpf_ktime_get_ns()-target_profile->last_seen)/NANO;
    if (elapsed_time > 0) {
        pps = (target_profile->cur_rx_packets-target_profile->pre_rx_packets)/elapsed_time;
        if (pps > 10000) {
            target_profile->action = XDP_DROP;
        } else {
            target_profile->action = XDP_PASS;
        }
        /* Update the statistics of traffic to current timestamp */
        xdp_icmp_suspect_catchup(ctx, bpf_ntohs(iphdr->saddr));
    }

    action = target_profile->action;

out:
    /* Record the action into the stats map and return the action value */
    return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
