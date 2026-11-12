// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct key4 { __u32 prefix; __u8 addr[4]; };
struct key6 { __u32 prefix; __u8 addr[16]; };
struct rule { __u64 expires_ns; __u32 id; __u32 pad; };
struct config { __u32 enforce; __u32 udp_pps_cpu; __u32 syn_pps_cpu; __u32 pad; };
struct count { __u64 packets, bytes; };
struct vlan { __be16 tci, proto; };
struct flow_key {
    __u8 src[16], dst[16];
    __u16 sport, dport, vlan_outer, vlan_inner;
    __u32 vni;
    __u8 family, protocol, direction, tagged;
    __u8 tunnel_src[16], tunnel_dst[16];
    __u16 overlay_outer, overlay_inner;
    __u8 overlay_tagged, tunnel_family, reserved[2];
};
struct flow_value { __u64 first_ns, last_ns, packets, bytes; __u32 flags, pad; };
#define MAP(name_, type_, key_, value_, max_) \
struct { __uint(type, type_); __uint(max_entries, max_); __type(key, key_); __type(value, value_); } name_ SEC(".maps")
struct { __uint(type, BPF_MAP_TYPE_LPM_TRIE); __uint(max_entries, 16384);
 __uint(map_flags, BPF_F_NO_PREALLOC); __type(key, struct key4); __type(value, struct rule);
} block4 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LPM_TRIE); __uint(max_entries, 16384);
 __uint(map_flags, BPF_F_NO_PREALLOC); __type(key, struct key6); __type(value, struct rule);
} block6 SEC(".maps");
MAP(settings, BPF_MAP_TYPE_ARRAY, __u32, struct config, 1);
// 0 ingress pass, 1 block candidate, 2 malformed, 3 flow insert failure,
// 4 egress, 5 UDP budget candidate, 6 SYN budget candidate, 7 unsupported.
MAP(stats, BPF_MAP_TYPE_PERCPU_ARRAY, __u32, struct count, 8);
MAP(rule_stats, BPF_MAP_TYPE_PERCPU_ARRAY, __u32, struct count, 4096);
MAP(flows, BPF_MAP_TYPE_LRU_HASH, struct flow_key, struct flow_value, 65536);
struct budget { __u64 second; __u32 udp, syn; };
MAP(budgets, BPF_MAP_TYPE_PERCPU_ARRAY, __u32, struct budget, 1);

static __always_inline void account(__u32 reason, __u64 bytes) {
 struct count *c = bpf_map_lookup_elem(&stats, &reason);
 if (c) { c->packets++; c->bytes += bytes; }
}
// Returns 0 parsed, 1 unsupported, -1 malformed. IPv4 fragments and IPv6
// extension chains are deliberately unsupported in this first version.
static __always_inline int parse_l2(void *data, void *end, struct flow_key *k, void **transport, void **limit) {
 struct ethhdr *eth = data;
 if ((void *)(eth + 1) > end) return -1;
 __be16 proto = eth->h_proto;
 void *p = eth + 1;
 #pragma unroll
 for (int i = 0; i < 2; i++) {
  if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
   struct vlan *v = p;
   if ((void *)(v + 1) > end) return -1;
   if (i == 0) k->vlan_outer = bpf_ntohs(v->tci) & 4095;
   else k->vlan_inner = bpf_ntohs(v->tci) & 4095;
   k->tagged++; proto = v->proto; p = v + 1;
  }
 }
 if (proto == bpf_htons(ETH_P_IP)) {
  struct iphdr *ip = p;
  if ((void *)(ip + 1) > end || ip->version != 4 || ip->ihl < 5) return -1;
  __u32 len = ip->ihl * 4;
  if (p + len > end || bpf_ntohs(ip->tot_len) < len || p + bpf_ntohs(ip->tot_len) > end) return -1;
  if (ip->frag_off & bpf_htons(0x3fff)) return 1;
  k->family = 4; k->protocol = ip->protocol;
  __builtin_memcpy(k->src, &ip->saddr, 4); __builtin_memcpy(k->dst, &ip->daddr, 4);
  end = p + bpf_ntohs(ip->tot_len); p += len;
 } else if (proto == bpf_htons(ETH_P_IPV6)) {
  struct ipv6hdr *ip = p;
  if ((void *)(ip + 1) > end || ip->version != 6) return -1;
  if ((void *)(ip + 1) + bpf_ntohs(ip->payload_len) > end) return -1;
  k->family = 6; k->protocol = ip->nexthdr;
  __builtin_memcpy(k->src, &ip->saddr, 16); __builtin_memcpy(k->dst, &ip->daddr, 16);
  end = (void *)(ip + 1) + bpf_ntohs(ip->payload_len); p = ip + 1;
 } else return 1;
 if (k->protocol == IPPROTO_TCP) {
  struct tcphdr *tcp = p;
  if ((void *)(tcp + 1) > end || tcp->doff < 5 || p + tcp->doff * 4 > end) return -1;
  k->sport = bpf_ntohs(tcp->source); k->dport = bpf_ntohs(tcp->dest);
 } else if (k->protocol == IPPROTO_UDP) {
  struct udphdr *udp = p;
  if ((void *)(udp + 1) > end || bpf_ntohs(udp->len) < 8 || p + bpf_ntohs(udp->len) > end) return -1;
  k->sport = bpf_ntohs(udp->source); k->dport = bpf_ntohs(udp->dest);
 } else if (k->protocol != IPPROTO_ICMP && k->protocol != IPPROTO_ICMPV6) return 1;
 *transport = p; *limit = end;
 return 0;
}
static __always_inline int parse(void *data, void *end, struct flow_key *k, __u32 *flags) {
 void *l4 = 0, *limit = 0;
 int ret = parse_l2(data, end, k, &l4, &limit);
 if (ret) return ret;
 if (k->protocol == IPPROTO_UDP && k->dport == 4789) {
  struct udphdr *udp = l4;
  if ((void *)(udp + 1) > end) return -1;
  __u8 *vx = (void *)(udp + 1);
  if ((void *)vx + 8 > limit || (void *)vx + 8 > end) return -1;
  // Base RFC7348 VXLAN only; other formats have explicit unsupported policy.
  if (vx[0] != 8 || vx[1] || vx[2] || vx[3] || vx[7]) return 1;
  __u32 vni = ((__u32)vx[4] << 16) | ((__u32)vx[5] << 8) | vx[6];
  struct flow_key inner = {};
  void *inner_l4 = 0, *inner_limit = 0;
  ret = parse_l2(vx + 8, (void *)udp + bpf_ntohs(udp->len), &inner, &inner_l4, &inner_limit);
  if (ret) return ret;
  __builtin_memcpy(k->tunnel_src, k->src, 16); __builtin_memcpy(k->tunnel_dst, k->dst, 16);
  k->tunnel_family = k->family;
  __builtin_memcpy(k->src, inner.src, 16); __builtin_memcpy(k->dst, inner.dst, 16);
  k->family = inner.family; k->protocol = inner.protocol;
  k->sport = inner.sport; k->dport = inner.dport; k->vni = vni;
  k->overlay_outer = inner.vlan_outer; k->overlay_inner = inner.vlan_inner; k->overlay_tagged = inner.tagged;
  l4 = inner_l4; limit = inner_limit;
 }
 if (k->protocol == IPPROTO_TCP) {
  __u8 *tcp = l4;
  if ((void *)tcp + 20 > end || (void *)tcp + 20 > limit) return -1;
  *flags = tcp[13];
 }
 return 0;
}
static __always_inline void track(struct flow_key *k, __u64 bytes, __u64 now, __u32 flags) {
 struct flow_value *f = bpf_map_lookup_elem(&flows, k);
 if (f) {
  __sync_fetch_and_add(&f->packets, 1); __sync_fetch_and_add(&f->bytes, bytes);
  // Concurrent writers can race on time; userspace uses an idle-time margin.
  f->last_ns = now; __sync_fetch_and_or(&f->flags, flags);
 } else {
  struct flow_value v = { .first_ns = now, .last_ns = now, .packets = 1, .bytes = bytes, .flags = flags };
  if (bpf_map_update_elem(&flows, k, &v, BPF_NOEXIST)) account(3, bytes);
 }
}
SEC("xdp") int ingress(struct xdp_md *ctx) {
 void *data = (void *)(long)ctx->data, *end = (void *)(long)ctx->data_end;
 __u64 bytes = end - data, now = bpf_ktime_get_ns();
 __u32 zero = 0;
 struct config *cfg = bpf_map_lookup_elem(&settings, &zero);
 struct flow_key k = {};
 __u32 flags = 0;
 int result = parse(data, end, &k, &flags);
 if (result) {
  account(result < 0 ? 2 : 7, bytes);
  return result < 0 && cfg && cfg->enforce ? XDP_DROP : XDP_PASS;
 }
 struct rule *r = 0;
 if (k.family == 4) { struct key4 key = { .prefix = 32 }; __builtin_memcpy(key.addr, k.src, 4); r = bpf_map_lookup_elem(&block4, &key); }
 else { struct key6 key = { .prefix = 128 }; __builtin_memcpy(key.addr, k.src, 16); r = bpf_map_lookup_elem(&block6, &key); }
 if (r && (!r->expires_ns || now < r->expires_ns)) {
  __u32 id = r->id;
  struct count *c = bpf_map_lookup_elem(&rule_stats, &id);
  if (c) { c->packets++; c->bytes += bytes; }
  account(1, bytes);
  if (cfg && cfg->enforce) return XDP_DROP;
 }
 track(&k, bytes, now, flags); account(0, bytes); return XDP_PASS;
}
SEC("tc") int egress(struct __sk_buff *skb) {
 void *data = (void *)(long)skb->data, *end = (void *)(long)skb->data_end;
 struct flow_key k = { .direction = 1 };
 __u32 flags = 0;
 if (!parse(data, end, &k, &flags)) track(&k, skb->len, bpf_ktime_get_ns(), flags);
 account(4, skb->len); return TC_ACT_OK;
}
char LICENSE[] SEC("license") = "GPL";

