#include <stdio.h>
#include <stdlib.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "process_packet.h"

int main(int argc, char **argv)
{
        struct nfq_handle *conn_handle;
        struct nfq_q_handle *q_handle;
        int fd;
        int rv;
        char buf[4096] __attribute__ ((aligned));

        printf("opening library handle\n");
        conn_handle = nfq_open();
        if (!conn_handle) {
                fprintf(stderr, "error during nfq_open()\n");
                exit(1);
        }

        printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
        if (nfq_unbind_pf(conn_handle, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_unbind_pf()\n");
                exit(1);
        }

        printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
        if (nfq_bind_pf(conn_handle, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_bind_pf()\n");
                exit(1);
        }

        printf("binding this socket to queue '0'\n");
        q_handle = nfq_create_queue(conn_handle,  0, &cb, NULL);
        if (!q_handle) {
                fprintf(stderr, "error during nfq_create_queue()\n");
                exit(1);
        }

        printf("setting copy_packet mode\n");
        if (nfq_set_mode(q_handle, NFQNL_COPY_PACKET, 0xffff) < 0) {
                fprintf(stderr, "can't set packet_copy mode\n");
                exit(1);
        }

        fd = nfq_fd(conn_handle);

        while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
                printf("pkt received\n");
                nfq_handle_packet(conn_handle, buf, rv);
        }

        printf("unbinding from queue 0\n");
        nfq_destroy_queue(q_handle);

#ifdef INSANE
        /* normally, applications SHOULD NOT issue this command, since
         * it detaches other programs/sockets from AF_INET, too ! */
        printf("unbinding from AF_INET\n");
        nfq_unbind_pf(conn_handle, AF_INET);
#endif

        printf("closing library handle\n");
        nfq_close(conn_handle);

        exit(0);
}
