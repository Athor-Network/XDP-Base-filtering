#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_ddos_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // Example: Drop packets from known bad IPs (hardcoded)
    if (src_ip == __constant_htonl(0xC0A80101)) // 192.168.1.1
        return XDP_DROP;

    // Drop malformed TCP SYN packets (SYN flood)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return XDP_DROP;

        if (tcp->syn && !tcp->ack && tcp->doff < 5)
            return XDP_DROP;
    }

    // Drop UDP packets with tiny payloads (UDP flood)
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip->ihl * 4;
        if ((void *)udp + sizeof(*udp) > data_end)
            return XDP_DROP;

        if (ntohs(udp->len) < 8)
            return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
