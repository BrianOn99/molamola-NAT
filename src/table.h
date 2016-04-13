int table_trans(int i);
struct ip_port * table_orig(int i);
int table_insert(struct ip_port *my_ip_port);
int table_find_rev(uint16_t *port);
int table_find(struct ip_port *my_ip_port);
void table_remove(int index);
int table_monitor_FIN(unsigned int index, struct tcphdr *tcph, int is_outbound);
void table_update_time(unsigned int index);
#ifndef NDEBUG
void table_print(FILE *output_dev);
#endif
