CC = gcc
CFLAG = -I .
DEFS = tftp.h
T1 = tftpserver
T2 = tftpclient

all : $(T1) $(T2)

%.o : %.c $(DEFS)
	$(CC) -c $< -o $@ $(CFLAG)

$(T1) : $(T1).o
	$(CC) -o $(T1) $(CFLAG)  $(T1).o
$(T2) : $(T2).o
	$(CC) -o $(T2) $(CFLAG) $(T2).o
	
clean: all
	rm *.o $(T2) $(T2)
.PHONY: clean
