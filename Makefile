CC = gcc
CFLAGS = -std=gnu99 -Wall -I.
CC_CMD = $(CC) $(CFLAGS) -o $@ -c $<

%.o: src/%.c
	$(CC_CMD)

nat: process_packet.o nat.o
	$(CC) $(CFLAGS) -o $@ $^ -lnfnetlink -lnetfilter_queue

clean:
	@rm -f nat *.o
