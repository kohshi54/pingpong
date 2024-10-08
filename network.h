// from lizrice project learning-ebpf/chapter8/network.h
// modified to reply 1.1.1.1

#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
//#include <linux/bpf.h>

static __always_inline unsigned short is_icmp_ping_request(void *data,
                                                           void *data_end) {
  struct ethhdr *eth = data;
  if (data + sizeof(struct ethhdr) > data_end)
    return 0;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return 0;

  struct iphdr *iph = data + sizeof(struct ethhdr);
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    return 0;

  if (iph->protocol != 0x01)
    // We're only interested in ICMP packets
    return 0;

  struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
          sizeof(struct icmphdr) >
      data_end)
    return 0;

  return (icmp->type == 8);
}

static __always_inline void swap_mac_addresses(struct __sk_buff *skb) {
  unsigned char src_mac[6];
  unsigned char dst_mac[6];
  bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_source), src_mac, 6);
  bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_dest), dst_mac, 6);
  bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), dst_mac, 6, 0);
  bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), src_mac, 6, 0);
}

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))

static __always_inline void swap_ip_addresses(struct __sk_buff *skb, bool disguise_flg) {
  unsigned char prev_src_ip[4];
  unsigned char prev_dst_ip[4];
  unsigned char src_ip_fake[4] = {1, 1, 1, 1};
  //__u32 new_ip = (1 << 24) & 0xFF + (1 << 16) & 0xFF + (1 << 8) & 0xFF + (1) & 0xFF;

  bpf_skb_load_bytes(skb, IP_SRC_OFF, prev_src_ip, 4);
  bpf_skb_load_bytes(skb, IP_DST_OFF, prev_dst_ip, 4);
  //bpf_skb_store_bytes(skb, IP_SRC_OFF, dst_ip, 4, 0);
  //bpf_skb_store_bytes(skb, IP_SRC_OFF, src_ip_fake, 4, BPF_F_RECOMPUTE_CSUM);

  __u32 *prev_src_ip_ptr = (__u32 *)prev_src_ip;
  __u32 *prev_dst_ip_ptr = (__u32 *)prev_dst_ip;
  __u32 *src_ip_fake_ptr = (__u32 *)src_ip_fake;

  if (disguise_flg) {
    bpf_skb_store_bytes(skb, IP_SRC_OFF, src_ip_fake, 4, 0);
    bpf_l3_csum_replace(skb, IP_CSUM_OFF, *prev_src_ip_ptr, *src_ip_fake_ptr, 4);
  } else {
    bpf_skb_store_bytes(skb, IP_SRC_OFF, prev_dst_ip, 4, 0);
    bpf_l3_csum_replace(skb, IP_CSUM_OFF, *prev_src_ip_ptr, *prev_dst_ip_ptr, 4);
  }

    bpf_skb_store_bytes(skb, IP_DST_OFF, prev_src_ip, 4, 0);
    bpf_l3_csum_replace(skb, IP_CSUM_OFF, *prev_dst_ip_ptr, *prev_src_ip_ptr, 4);

}

#define ICMP_CSUM_OFF   (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF   (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))

static __always_inline void update_icmp_type(struct __sk_buff *skb,
                                             unsigned char old_type,
                                             unsigned char new_type) {
  bpf_l4_csum_replace(skb, ICMP_CSUM_OFF, old_type, new_type, 2);
  bpf_skb_store_bytes(skb, ICMP_TYPE_OFF, &new_type, sizeof(new_type), 0);
}
