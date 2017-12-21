CC = gcc
CFLAG = -I .
DEFS = tftp.h

all : server client

%.o : %.c $(DEFS)
	$(CC) -c $< -o $@ $(CFLAG)

server : tftpserver.o
	$(CC) -o server $(CFLAG)  tftpserver.o
client : tftpclient.o
	$(CC) -o client $(CFLAG) tftpclient.o
	
clean: all
	rm *.o server client
.PHONY: clean
