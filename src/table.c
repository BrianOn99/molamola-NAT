/*
 * The network translation table.  All port in network byte order
 */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/tcp.h>
#include <time.h>
#include "ip_port.h"
#define MIN_OUT_PORT 10000
#define MAX_OUT_PORT 12001  /* exclusive */
#define TABLE_SIZE (MAX_OUT_PORT-MIN_OUT_PORT)

enum fin_state { FIN_NOT = 0, FIN_ASK_1, FIN_ACK_1, FIN_ASK_2 };

struct table_entry {
        struct ip_port orig;
        uint16_t transfrom_port;
        enum fin_state fin_s;
        uint32_t fin_ack;
        char fin_init_by_us;
        time_t last_time;
};

static struct table_entry table[TABLE_SIZE];
static unsigned int table_item_num = 0;
/* record which port is consumed.  First item correspond to MIN_OUT_PORT */
static char consumed_port[MAX_OUT_PORT-MIN_OUT_PORT];

#ifndef NDEBUG
void table_print(FILE *output_dev)
{
        fprintf(output_dev, "=====Translation Table=====\n");
        fprintf(output_dev, "%-20s | %-10s | %-5s | %-15s\n", "from", "to", "state", "last time");
        for (int i=0; i < table_item_num; i++) {
                fprintf(output_dev, "%-11s :%-7d | %-10d | %1d | %-15s\n",
                        inet_ntoa((struct in_addr){table[i].orig.ip}),
                        ntohs(table[i].orig.port),
                        ntohs(table[i].transfrom_port),
                        table[i].fin_s,
                        ctime(&table[i].last_time));
        }
        fprintf(output_dev, "\n");
}
#endif

int table_find(struct ip_port *my_ip_port)
{
        for (int i=0; i < table_item_num; i++) {
                if (memcmp(my_ip_port, &(table[i].orig), sizeof(*my_ip_port)) == 0)
                        return i;
        }
        return -1;
}

int table_find_rev(uint16_t *port)
{
        for (int i=0; i < table_item_num; i++) {
                if (memcmp(port, &(table[i].transfrom_port), sizeof(*port)) == 0)
                        return i;
        }
        return -1;
}

void table_remove(int index)
{
        uint16_t using_port = ntohs(table[index].transfrom_port);
        consumed_port[using_port - MIN_OUT_PORT] = 0;
        /* remove the item by overwriting */
        if (table_item_num > 1) {
                //printf("overwriting from %d to %d\n", table_item_num-1, index);
                memcpy(&table[index], &table[table_item_num-1], sizeof(table[0]));
        }
        //printf("clearing index %d\n", table_item_num-1);
        memset(&table[table_item_num-1], '\0', sizeof(table[0]));
        table_item_num--;
}

/*
 * get the transformed port
 */
int table_trans(int i)
{
        assert(i >= 0);
        return table[i].transfrom_port;
}

/*
 * get the original ip and port
 */
struct ip_port * table_orig(int i)
{
        assert(i >= 0);
        return &(table[i].orig);
}

/*
 * consume smallest available port
 */
static int take_next_port()
{
        for (int i=0; i < sizeof(consumed_port)/sizeof(*consumed_port); i++) {
                if (!consumed_port[i]) {
                        consumed_port[i] = 1;
                        return htons(i + MIN_OUT_PORT);
                }
        }
        return -1;
}

/*
 * insert new ip-port pair and return transformed port
 */
int table_insert(struct ip_port *my_ip_port)
{
        if (table_item_num >= TABLE_SIZE) {
                fprintf(stderr, "too many entries\n");
                return -1;
        }
        struct table_entry *next = &table[table_item_num];
        next->orig = *my_ip_port;
        next->transfrom_port = take_next_port();
        next->last_time = time(NULL);
        assert(next->transfrom_port != -1);
        table_item_num++;
        return next->transfrom_port;
}

void table_update_time(unsigned int index)
{
        table[index].last_time = time(NULL);
}

/*
 * check FIN flag.  return 1 if removed from table else 0
 */
int table_monitor_FIN(unsigned int index, struct tcphdr *tcph, int is_outbound)
{
        struct table_entry *entry = &table[index];
        switch (entry->fin_s) {
        case FIN_NOT:
                if (tcph->fin) {
                        entry->fin_init_by_us = is_outbound;
                        entry->fin_ack = tcph->ack;
                        entry->fin_s= FIN_ASK_1;
                        //puts("goto A");
                }
                return 0;
        case FIN_ASK_1:
                if (entry->fin_init_by_us == is_outbound)
                        break;
                if (!(entry->fin_ack <= tcph->seq))
                        break;
                entry->fin_s= FIN_ACK_1;
                //puts("goto B");
                /* fall throygh */
        case FIN_ACK_1:
                if (entry->fin_init_by_us == is_outbound)
                        break;
                if (tcph->fin) {
                        entry->fin_ack = tcph->ack;
                        entry->fin_s= FIN_ASK_2;
                        //puts("goto C");
                }
                return 0;
        case FIN_ASK_2:
                if (entry->fin_init_by_us != is_outbound)
                        break;
                if (entry->fin_ack <= tcph->seq) {
                        table_remove(index);
                        entry->fin_s= FIN_NOT;
                        //puts("goto FINISHED");
                }
                return 1;
        default:
                printf("Error: unhandled state %d.  Should not reach here\n",
                       entry->fin_s);
        }
        return 0;
}
