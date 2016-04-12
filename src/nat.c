#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "process_packet.h"

static void die_if(int val, char *msg)
{
        if (val) {
                fputs(msg, stderr);
                exit(1);
        }
}

static void usage()
{
        puts("Usage:");
        puts("./nat <public ip> <internal ip> <subnet mask>");
}

static int get_interface_index(struct in_addr *target_addr)
{
        struct ifaddrs *ifaddrs, *ifa;
        int result = -1;
	if (getifaddrs(&ifaddrs) < 0)
		return -1;
	for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr) continue;
                struct sockaddr_in *addr = (void*)(ifa->ifa_addr);
                if (addr->sin_addr.s_addr == target_addr->s_addr) {
                        result = if_nametoindex(ifa->ifa_name);
                        break;
                }
	}
	freeifaddrs(ifaddrs);
        return result;
}

int main(int argc, char **argv)
{
        if (argc < 2) {
                usage();
                exit(1);
        }

        char *pub_ip_str = argv[1];
        struct in_addr public_addr;
        if (!inet_aton(pub_ip_str, &public_addr)) {
                perror("inet_aton on pulic ip");
                usage();
                exit(1);
        }
        pub_interface_ip = public_addr.s_addr;

        pub_interface_index = get_interface_index(&public_addr);
        if (pub_interface_index == -1) {
                fprintf(stderr, "Some problem with given public ip\n");
                exit(1);
        }
        printf("using interface index %d to go out\n", pub_interface_index);

#if 0 /* some code suggested by tutorial notes */
        struct in_addr local_addr;
        if (!inet_aton(argv[2], &local_addr)) {
                perror("inet_aton");
                usage();
                exit(1);
        }
        int mask_int = atoi(argv[3]);
        local_mask = 0xffffffff << (32 - mask_int);
        local_network = local_addr.s_addr && local_mask;
#endif

        struct nfq_handle *conn_handle;
        struct nfq_q_handle *q_handle;

        /* open library handle */
        conn_handle = nfq_open();
        die_if(!conn_handle, "error during nfq_open()");

        /* unbinding existing nf_queue handler for AF_INET (if any) */
        die_if(nfq_unbind_pf(conn_handle, AF_INET) < 0, "error during nfq_unbind_pf()\n");

        /* binding nfnetlink_queue as nf_queue handler for AF_INET */
        die_if(nfq_bind_pf(conn_handle, AF_INET) < 0, "error during nfq_bind_pf()\n");

        /* binding this socket to queue '0' */
        q_handle = nfq_create_queue(conn_handle,  0, &process_packet, NULL);
        die_if(!q_handle,
               "error during nfq_create_queue(), probably another application is running\n");

        /* setting copy_packet mode */
        die_if(nfq_set_mode(q_handle, NFQNL_COPY_PACKET, 0xffff) < 0,
               "can't set packet_copy mode\n");

        int fd = nfq_fd(conn_handle);

        int rv;
        char buf[4096] __attribute__ ((aligned));
        while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
                nfq_handle_packet(conn_handle, buf, rv);
        }

        /* unbinding from queue 0 */
        nfq_destroy_queue(q_handle);

#ifdef INSANE
        /* normally, applications SHOULD NOT issue this command, since
         * it detaches other programs/sockets from AF_INET, too ! */
        /* unbinding from AF_INET */
        nfq_unbind_pf(conn_handle, AF_INET);
#endif

        printf("closing library handle\n");
        nfq_close(conn_handle);

        return 0;
}
