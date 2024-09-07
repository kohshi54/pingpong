#include "network.h"
#include <bcc/proto.h>
//#include <linux/pkts_cls.h>
#include <net/pkt_cls.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
//#include <linux/bpf.h>
#include <linux/inet.h>
#include <net/checksum.h>

//#include <linux/skbuff.h>

typedef struct data_t {
    __u32 saddr;
    __u32 daddr;
} t_data;
BPF_PERF_OUTPUT(events); // saddr print suru tame

typedef enum e_prog_mode {
    NORMAL,
    DISGUISE,
    BAIGAESHI,
    SUPER_BOT_FIGHT,
} t_prog_mode;

//BPF_HASH(pong_mode, t_prog_mode, bool);
//BPF_HASH(pong_mode, u32, t_prog_mode);
BPF_HASH(pong_mode, u32, u32);


/*
static inline void csum_replace2(uint16_t *sum, uint16_t old, uint16_t new)
{
	uint16_t csum = ~*sum;

	csum += ~old;
	csum += csum < (uint16_t)~old;

	csum += new;
	csum += csum < (uint16_t)new;

	*sum = ~csum;
}
*/

int tc_pingpong(struct __sk_buff *skb) {
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (!is_icmp_ping_request(data, data_end)) {
		return TC_ACT_OK;
	}

	struct iphdr *iph = data + sizeof(struct ethhdr);
	struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

	__u32 src_ip = ntohl(iph->saddr);
	__u32 dst_ip = ntohl(iph->daddr);
    t_data event = {src_ip, dst_ip};
    events.perf_submit(skb, &event, sizeof(event)); // user kuukannni watasutameni map (perf output) ni ierru

/*
	bpf_trace_printk("[action] IP Packet, proto= %d", iph->protocol);
	// separete because bpf_trace_printk limit its max args to 3.
	bpf_trace_printk("src= %d.%d", (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF);
	bpf_trace_printk(".%d.%d", (src_ip >> 8) & 0xFF, src_ip & 0xFF);
	bpf_trace_printk("dst= %d.%d", (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF);
	bpf_trace_printk(".%d.%d\n", (dst_ip >> 8) & 0xFF, dst_ip & 0xFF);
*/

	uint8_t old_ttl = iph->ttl;
	iph->ttl = 125;
	csum_replace2(&iph->check, htons(old_ttl << 8), htons(iph->ttl << 8));

    int key = 0;
    u32 *mode = pong_mode.lookup(&key);

    bool disguise_flg = (mode && *mode == DISGUISE);
	swap_mac_addresses(skb);
	swap_ip_addresses(skb, disguise_flg);
	//iph->daddr = (1 << 24) & 0xFF + (1 << 16) & 0xFF + (1 << 8) & 0xFF + (1 & 0xFF);
	update_icmp_type(skb, 8, 0);
	//bpf_clone_redirect(skb, skb->ifindex, 0);
    
    if (mode && *mode == NORMAL) {
	    bpf_clone_redirect(skb, skb->ifindex, 0);
    }
    if (mode && *mode == DISGUISE) {
	    bpf_clone_redirect(skb, skb->ifindex, 0);
    }
    if (mode && *mode == BAIGAESHI) {
	    bpf_clone_redirect(skb, skb->ifindex, 0);
	    bpf_clone_redirect(skb, skb->ifindex, 0);
    }
    if (mode && *mode == SUPER_BOT_FIGHT) {
        for (int i = 0; i < 100; i++) { // hyakubaigaeshi
	        bpf_clone_redirect(skb, skb->ifindex, 0);
        }
    }

   	
	return TC_ACT_SHOT;
}

