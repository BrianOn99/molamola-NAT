#include <stdint.h>
int process_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
extern int pub_interface_index;
