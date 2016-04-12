int table_orig2trans(struct ip_port *my_ip_port);
struct ip_port * table_trans2orig(uint16_t *port);
int table_insert(struct ip_port *my_ip_port);
int table_find_rev(uint16_t *port);
int table_find(struct ip_port *my_ip_port);
void table_remove(int index);
#ifndef NDEBUG
void table_print(FILE *output_dev);
#endif
