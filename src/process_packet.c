#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>

void processPacketData (char *data, int size) {
        FILE *outFile;

        outFile = fopen ("/tmp/packetData.txt", "w");
        fwrite (data, size, 1, outFile);
        fclose (outFile);
}


#if 0  /* sample code */
/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
        int id = 0;
        struct nfqnl_msg_packet_hdr *ph;
        struct nfqnl_msg_packet_hw *hwph;
        u_int32_t mark,ifi; 
        int ret;
        char *data;

        ph = nfq_get_msg_packet_hdr(tb);
        if (ph) {
                id = ntohl(ph->packet_id);
                printf("hw_protocol=0x%04x hook=%u id=%u ",
                       ntohs(ph->hw_protocol), ph->hook, id);
        }

        hwph = nfq_get_packet_hw(tb);
        if (hwph) {
                int i, hlen = ntohs(hwph->hw_addrlen);

                printf("hw_src_addr=");
                for (i = 0; i < hlen-1; i++)
                        printf("%02x:", hwph->hw_addr[i]);
                printf("%02x ", hwph->hw_addr[hlen-1]);
        }

        mark = nfq_get_nfmark(tb);
        if (mark)
                printf("mark=%u ", mark);

        ifi = nfq_get_indev(tb);
        if (ifi)
                printf("indev=%u ", ifi);

        ifi = nfq_get_outdev(tb);
        if (ifi)
                printf("outdev=%u ", ifi);
        ifi = nfq_get_physindev(tb);
        if (ifi)
                printf("physindev=%u ", ifi);

        ifi = nfq_get_physoutdev(tb);
        if (ifi)
                printf("physoutdev=%u ", ifi);

        ret = nfq_get_payload(tb, &data);
        if (ret >= 0) {
                printf("payload_len=%d ", ret);
                processPacketData (data, ret);
        }
        fputc('\n', stdout);

        return id;
}
#endif

/*
 * Copied from doxygen documentation:
 * q_handle: the queue handle returned by nfq_create_queue
 * nfmsg: message objetc that contains the packet (I think it is wrong)
 * nfad: Netlink packet data handle
 * data: he value passed to the data parameter of nfq_create_queue
 */
int process_packet(struct nfq_q_handle *q_handle, struct nfgenmsg *nfmsg,
                   struct nfq_data *nfad, void *data)
{
        char *payload;
        int payload_len = nfq_get_payload(nfad, &payload);
        if (payload_len == -1) {
                fprintf(stderr, "Error: cannot get payload\n");
                return -1;
        }

        struct iphdr *iph = (struct iphdr*)payload;

        if (iph->protocol != IPPROTO_TCP) {
                fprintf(stderr, "Error: non-TCP received. "
                                "iptabes is not set correctly?\nk");
                return -1;
        }

        uint32_t id = ntohl(nfq_get_msg_packet_hdr(nfad)->packet_id);
        return nfq_set_verdict(q_handle, id, NF_ACCEPT, 0, NULL);
}
