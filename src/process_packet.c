#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "ip_port.h"
#include "table.h"
#include "checksum.h"

int pub_interface_index = 0;
uint32_t pub_interface_ip = 0;

#ifdef _DEBUG
#include <arpa/inet.h>
static void _debug_ip_port(char *msg, struct ip_port *s)
{
        puts(msg);
        printf("ip: ");
        puts(inet_ntoa((struct in_addr){s->ip}));
        printf("port: %d\n", ntohs(s->port));
}
#else
static void _debug_ip_port(char *msg, struct ip_port *s) {}
#endif

#if 0  /* sample code */
void processPacketData (char *data, int size) {
        FILE *outFile;

        outFile = fopen ("/tmp/packetData.txt", "w");
        fwrite (data, size, 1, outFile);
        fclose (outFile);
}

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

static struct tcphdr * locate_tcp(struct iphdr *iph)
{
        return (struct tcphdr *) (((char*) iph) + (iph->ihl << 2));
}

static int come_from_outside(struct nfq_data *nfad)
{
        return nfq_get_indev(nfad) == pub_interface_index;
}

/*
 * handle the case packet is outbound but no table entry yet.
 * Return new port if no error
 */
static int
outbound_new_getport(struct tcphdr *tcph, struct ip_port *my_ip_port)
{
        if (tcph->syn) {
                puts("get new connection");
                return table_insert(my_ip_port);
        } else {
                puts("syn not set");
                return -1;
        }
}

static void
transform_to_out(struct iphdr *iph, struct tcphdr *tcph, uint16_t trans_port)
{
        iph->saddr = pub_interface_ip;
        tcph->source = trans_port;
        iph->check = ip_checksum((unsigned char *)iph);
        tcph->check = tcp_checksum((unsigned char *)iph);
}

static void
transform_to_in(struct iphdr *iph, struct tcphdr *tcph, struct ip_port *orig_ip_port)
{
        iph->daddr = orig_ip_port->ip;
        tcph->dest = orig_ip_port->port;
        iph->check = ip_checksum((unsigned char *)iph);
        tcph->check = tcp_checksum((unsigned char *)iph);
}

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
        uint32_t id = ntohl(nfq_get_msg_packet_hdr(nfad)->packet_id);
        unsigned char *payload;
        int payload_len = nfq_get_payload(nfad, &payload);
        if (payload_len == -1) {
                fprintf(stderr, "Error: cannot get payload\n");
                return -1;
        }

        struct iphdr *iph = (struct iphdr*)payload;

        if (iph->protocol != IPPROTO_TCP) {
                fprintf(stderr, "Error: non-TCP received. "
                                "iptabes is not set correctly?\nk");
                goto drop_packet;
        }
        
        struct tcphdr* tcph = locate_tcp(iph);
        if (!come_from_outside(nfad)) {
                puts("get outbound packet");
                struct ip_port my_ip_port = {
                        iph->saddr,
                        tcph->source
                };
                _debug_ip_port("Outbound:", &my_ip_port);
                int trans_port = table_orig2trans(&my_ip_port);
                if (trans_port == -1) {  /* not found */
                        trans_port = outbound_new_getport(tcph, &my_ip_port);
                        if (trans_port == -1)
                                goto drop_packet;
                } else {
                        puts("found entry");
                }
                transform_to_out(iph, tcph, trans_port);
        } else {
                puts("get inbound packet");
                struct ip_port *orig_ip_port = table_trans2orig(&(tcph->dest));
                if (orig_ip_port == NULL)
                        goto drop_packet;
                transform_to_in(iph, tcph, orig_ip_port);
        }

        int ret = nfq_set_verdict(q_handle, id, NF_ACCEPT, payload_len, payload);
        printf("accept packet: ret %d\n", ret);
        return ret;

drop_packet:
        puts("drop packet");
        return nfq_set_verdict(q_handle, id, NF_DROP, 0, NULL);
}
