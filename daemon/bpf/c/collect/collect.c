#include <uapi/linux/bpf.h>
#include <uapi/linux/in.h>
#include <uapi/linux/if.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/if_tunnel.h>
#include <bpf/bpf_helpers.h>
#include "bpf_legacy.h"
#define IP_MF		0x2000
#define IP_OFFSET	0x1FFF

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

// flow_record flow请求记录
struct flow_record {
	__be32 src;  // 源地址
	__be32 dst;  // 目的地址
	union {  // 端口
		__be32 ports;
		__be16 port16[2];
	};
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} records SEC(".maps");


static inline int proto_ports_offset(__u64 proto)
{
	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_DCCP:
	case IPPROTO_ESP:
	case IPPROTO_SCTP:
	case IPPROTO_UDPLITE:
		return 0;
	case IPPROTO_AH:
		return 4;
	default:
		return 0;
	}
}

static inline int ip_is_fragment(struct __sk_buff *ctx, __u64 nhoff)
{
	return load_half(ctx, nhoff + offsetof(struct iphdr, frag_off))
		& (IP_MF | IP_OFFSET);
}

static inline __u32 ipv6_addr_hash(struct __sk_buff *ctx, __u64 off)
{
	__u64 w0 = load_word(ctx, off);
	__u64 w1 = load_word(ctx, off + 4);
	__u64 w2 = load_word(ctx, off + 8);
	__u64 w3 = load_word(ctx, off + 12);

	return (__u32)(w0 ^ w1 ^ w2 ^ w3);
}

static inline __u64 parse_ip(struct __sk_buff *skb, __u64 nhoff, __u64 *ip_proto,
			     struct flow_record *flow)
{
	__u64 verlen;

	if (ip_is_fragment(skb, nhoff))
		*ip_proto = 0;
	else
		*ip_proto = load_byte(skb, nhoff + offsetof(struct iphdr, protocol));

	if (*ip_proto != IPPROTO_GRE) {
		flow->src = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
		flow->dst = load_word(skb, nhoff + offsetof(struct iphdr, daddr));
	}

	verlen = load_byte(skb, nhoff + 0/*offsetof(struct iphdr, ihl)*/);
	if (verlen == 0x45)
		nhoff += 20;
	else
		nhoff += (verlen & 0xF) << 2;

	return nhoff;
}

static inline __u64 parse_ipv6(struct __sk_buff *skb, __u64 nhoff, __u64 *ip_proto,
			       struct flow_record *flow)
{
	*ip_proto = load_byte(skb,
			      nhoff + offsetof(struct ipv6hdr, nexthdr));
	flow->src = ipv6_addr_hash(skb,
				   nhoff + offsetof(struct ipv6hdr, saddr));
	flow->dst = ipv6_addr_hash(skb,
				   nhoff + offsetof(struct ipv6hdr, daddr));
	nhoff += sizeof(struct ipv6hdr);

	return nhoff;
}

static inline bool flow_dissector(struct __sk_buff *skb,
				  struct flow_record *flow)
{
	__u64 nhoff = ETH_HLEN;
	__u64 ip_proto;
	__u64 proto = load_half(skb, 12);
	int poff;

	if (proto == ETH_P_8021AD) {
		proto = load_half(skb, nhoff + offsetof(struct vlan_hdr,
							h_vlan_encapsulated_proto));
		nhoff += sizeof(struct vlan_hdr);
	}

	if (proto == ETH_P_8021Q) {
		proto = load_half(skb, nhoff + offsetof(struct vlan_hdr,
							h_vlan_encapsulated_proto));
		nhoff += sizeof(struct vlan_hdr);
	}

	if (proto == ETH_P_IP)
		nhoff = parse_ip(skb, nhoff, &ip_proto, flow);
	else if (proto == ETH_P_IPV6)
		nhoff = parse_ipv6(skb, nhoff, &ip_proto, flow);
	else
		return false;

	switch (ip_proto) {
	case IPPROTO_GRE: {
		struct gre_hdr {
			__be16 flags;
			__be16 proto;
		};

		__u64 gre_flags = load_half(skb,
					    nhoff + offsetof(struct gre_hdr, flags));
		__u64 gre_proto = load_half(skb,
					    nhoff + offsetof(struct gre_hdr, proto));

		if (gre_flags & (GRE_VERSION|GRE_ROUTING))
			break;

		proto = gre_proto;
		nhoff += 4;
		if (gre_flags & GRE_CSUM)
			nhoff += 4;
		if (gre_flags & GRE_KEY)
			nhoff += 4;
		if (gre_flags & GRE_SEQ)
			nhoff += 4;

		if (proto == ETH_P_8021Q) {
			proto = load_half(skb,
					  nhoff + offsetof(struct vlan_hdr,
							   h_vlan_encapsulated_proto));
			nhoff += sizeof(struct vlan_hdr);
		}

		if (proto == ETH_P_IP)
			nhoff = parse_ip(skb, nhoff, &ip_proto, flow);
		else if (proto == ETH_P_IPV6)
			nhoff = parse_ipv6(skb, nhoff, &ip_proto, flow);
		else
			return false;
		break;
	}
	case IPPROTO_IPIP:
		nhoff = parse_ip(skb, nhoff, &ip_proto, flow);
		break;
	case IPPROTO_IPV6:
		nhoff = parse_ipv6(skb, nhoff, &ip_proto, flow);
		break;
	default:
		break;
	}

	poff = proto_ports_offset(ip_proto);
	if (poff >= 0) {
		nhoff += poff;
		flow->ports = load_word(skb, nhoff);
	}

	return true;
}

SEC("socket")
int collect(struct __sk_buff *skb)
{
	struct flow_record flow = {};
	if (!flow_dissector(skb, &flow))
		return 0;
    struct flow_record *fr;
    fr = bpf_ringbuf_reserve(&records, sizeof(struct flow_record), 0);
    if (!fr) {
        char err_msg[] = "bpf_ringbuf_reverse failed";
        bpf_trace_printk(err_msg, sizeof(err_msg));
        return 0;
    }
    fr->dst = flow.dst;
    fr->src = flow.src;
    fr->port16[0] = flow.port16[1];
    fr->port16[1] = flow.port16[0];

    bpf_ringbuf_submit(fr, 0);
  return 0;
}

char _license[] SEC("license") = "GPL";