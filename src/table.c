/*
 * The network translation table.  All port in network byte order
 */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include "ip_port.h"
#define MIN_OUT_PORT 10000
#define MAX_OUT_PORT 12001  /* exclusive */
#define TABLE_SIZE (MAX_OUT_PORT-MIN_OUT_PORT)

struct table_entry {
        struct ip_port orig;
        uint16_t transfrom_port;
};
static struct table_entry table[TABLE_SIZE];
static unsigned int table_item_num = 0;
/* record which port is consumed.  First item correspond to MIN_OUT_PORT */
static char consumed_port[MAX_OUT_PORT-MIN_OUT_PORT];

static int table_find(struct ip_port *my_ip_port)
{
        for (int i=0; i < table_item_num; i++) {
                if (memcmp(my_ip_port, &(table[i].orig), sizeof(*my_ip_port)) == 0)
                        return i;
        }
        return -1;
}

static int table_find_rev(uint16_t *port)
{
        for (int i=0; i < table_item_num; i++) {
                if (memcmp(port, &(table[i].transfrom_port), sizeof(*port)) == 0)
                        return i;
        }
        return -1;
}

/*
 * get the transformed port
 */
int table_orig2trans(struct ip_port *my_ip_port)
{
        int i = table_find(my_ip_port);
        if (i == -1)
                return -1;
        else
                return table[i].transfrom_port;
}

/*
 * get the original ip and port
 */
struct ip_port * table_trans2orig(uint16_t *port)
{
        int i = table_find_rev(port);
        if (i == -1)
                return NULL;
        else
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
        assert(next->transfrom_port != -1);
        table_item_num++;
        return next->transfrom_port;
}
