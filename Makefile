CC = gcc
CFLAGS = -std=gnu99 -Wall -I.
CC_CMD = $(CC) $(CFLAGS) -o $@ -c $<

%.o: src/%.c
	$(CC_CMD)

no_debug: CFLAGS += -DNDEBUG -O1
no_debug: nat

debug: CFLAGS += -g -O0
debug: nat

nat: process_packet.o nat.o table.o checksum.o
	$(CC) $(CFLAGS) -o $@ $^ -lnfnetlink -lnetfilter_queue

process_packet.o: table.o checksum.o

clean:
	@rm -f nat *.o
