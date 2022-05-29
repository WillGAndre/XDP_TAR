#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
	(Results from assignment resolution -> https://github.com/xdp-project/xdp-tutorial/tree/master/packet03-redirecting)
	ALL PARSER/HELPER FUNCTIONS TAKEN FROM COMMON
		(xdp-project/xdp-tutorial - https://github.com/xdp-project/xdp-tutorial)
*/

#include "common/parsing_helpers.h"
#include "common/rewrite_helpers.h"

// Defines xdp_stats_map 
#include "common/xdp_stats_kern_user.h"
#include "common/xdp_stats_kern.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

struct bpf_map_def SEC("maps") tx_port = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") redirect_params = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = ETH_ALEN,
	.value_size = ETH_ALEN,
	.max_entries = 1,
};

SEC("xdp_icmp_echo")
int xdp_icmp_echo_server(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
	int icmp_type;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	__u16 echo_reply, old_csum;
	struct icmphdr_common *icmphdr_res;
	struct icmphdr_common icmphdr_old;
	__u32 action = XDP_PASS;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	// Parse eth and IP
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_ICMP)
			goto out;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_ICMPV6)
			goto out;
	} else {
		goto out;
	}

	// Parse for ICMPv4 or ICMPv6
	icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr_res);
	if (eth_type == bpf_htons(ETH_P_IP) && icmp_type == ICMP_ECHO) {
		/* Swap IP source and destination */
		swap_src_dst_ipv4(iphdr);
		echo_reply = ICMP_ECHOREPLY;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)
		   && icmp_type == ICMPV6_ECHO_REQUEST) {
		/* Swap IPv6 source and destination */
		swap_src_dst_ipv6(ipv6hdr);
		echo_reply = ICMPV6_ECHO_REPLY;
	} else {
		goto out;
	}

	// Swap ethernet src and dest + update packet
	swap_src_dst_mac(eth);
	old_csum = icmphdr_res->cksum;
	icmphdr_res->cksum = 0;
	icmphdr_old = *icmphdr;
	icmphdr_res->type = echo_reply;
	// Get new checksum, source from assignment resolutions
	icmphdr_res->cksum = icmp_checksum_diff(~old_csum, icmphdr, &icmphdr_old);

	action = XDP_TX;

out:
	return xdp_stats_record_action(ctx, action);
}

// Calc new checksum (source: xdp-project/xdp-tutorial)
static __always_inline __u16 csum_fold_helper(__u32 csum) {
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

// Sizes should be multiple of 4 , due to 32-bit words 
static __always_inline __u16 icmp_checksum_diff(
		__u16 seed,
		struct icmphdr_common *icmphdr_new,
		struct icmphdr_common *icmphdr_old) {
	__u32 csum, size = sizeof(struct icmphdr_common);

	csum = bpf_csum_diff((__be32 *)icmphdr_old, size, (__be32 *)icmphdr_new, size, seed);
	return csum_fold_helper(csum);
}

#undef AF_INET
#define AF_INET 2
#undef AF_INET6
#define AF_INET6 10
#define IPV6_FLOWINFO_MASK bpf_htonl(0x0FFFFFFF)

char _license[] SEC("license") = "GPL";
