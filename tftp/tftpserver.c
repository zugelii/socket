#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include "tftp.h"
#include <errno.h>
#include <sys/select.h>
#include <errno.h>
#define MAX_LINE 100





fd_set read_set,write_set;
TFTPD client_head;

tftp_connection_args *tftp_quene;

int max_fd;

tftp_opcode tftp_decode_op(char *buf)
{
	return (tftp_opcode)(buf[1]);
}

u16_t tftp_extract_block(char *buf)
{
	u16_t *b = (u16_t*)buf;
	return ntohs(b[1]);
}

void tftp_extract_filename(char *fname, char *buf)
{
	strncpy(fname, buf + 2, 30);
}

void tftp_set_opcode(char *buffer, tftp_opcode opcode)
{
	buffer[0] = 0;
	buffer[1] = opcode;
}

void tftp_set_errorcode(char *buffer, tftp_errorcode opcode)
{
	buffer[2] = 0;
	buffer[3] = opcode;
}

void tftp_set_errormsg(char *buffer, char * errormsg)
{
	strcpy(buffer + 4, errormsg);
}

void tftp_set_block(char * packet, u16_t block)
{
	u16_t *p = (u16_t *)packet;
	p[1] = htons(block);
}

void tftp_set_data_message(char *packet, char *buf, int buflen)
{
	memcpy(packet + 4, buf, buflen);
}

u32_t tftp_is_correct_ack(char *buf, int block)
{
	if(tftp_decode_op(buf) != TFTP_ACK) return 0;
	if(block != tftp_extract_block(buf)) return 0;
	return 1;
}

int tftp_server_fd = 0;
/* tftp_errorcode error strings */
char *tftp_errorcode_string[] = {
                                  "not defined",
                                  "file not found",
                                  "access violation",
                                  "disk full",
                                  "illegal operation",
                                  "unknown transfer id",
                                  "file already exists",
                                  "no such user",
                                };

int tftp_send_message(int s_fd, struct sockaddr * addr, char *buf, int buflen)
{
	int n;
	char buf_loc = (char *)malloc(buflen);
	memcpy(buf_loc, buf, buflen);
	n = sendto(s_fd, buf_loc, n, 0, addr, sizeof(struct sockaddr)); //
	free(buf_loc);
	return n;
}

/* construct an error message into buf using err as the error code */
int tftp_construct_error_message(char *buf, tftp_errorcode err)
{

  int errorlen;
  /* Set the opcode in the 2 first bytes */
  tftp_set_opcode(buf, TFTP_ERROR);
  /* Set the errorcode in the 2 second bytes  */
  tftp_set_errorcode(buf, err);
  /* Set the error message in the last bytes */
  tftp_set_errormsg(buf, tftp_errorcode_string[err]);
  /* Set the length of the error message  */
  errorlen = strlen(tftp_errorcode_string[err]);

  /* return message size */
  return 4 + errorlen + 1;
}

/* construct and send an error message back to client */
int tftp_send_error_message(int s_fd, struct sockaddr *to, tftp_errorcode err)
{
  char buf[512];
  int error_len;

  /* construct error */
  error_len = tftp_construct_error_message(buf, err);
  /* sEndTransfererror  */
  return tftp_send_message(s_fd, to, buf, error_len);
}


/* construct and send a data packet */
int tftp_send_data_packet(int s_fd,  struct sockeaddr *to,  int block, char *buf, int buflen)
{
  //char packet[TFTP_DATA_PKT_LEN_MAX]; /* (512+4) bytes */
  //memset(packet, 'a', TFTP_DATA_PKT_LEN_MAX);
  /* Set the opcode 3 in the 2 first bytes */
  tftp_set_opcode(buf, TFTP_DATA);
  /* Set the block numero in the 2 second bytes */
  tftp_set_block(buf, block);
  /* Set the data message in the n last bytes */
  //@@@@tftp_set_data_message(packet, buf, buflen);
  //tftp_set_data_message(packet, packet, buflen);
  /* SEndTransferthe DATA packet */
  return tftp_send_message(s_fd, to, buf, buflen + 4);
}


int tftp_send_ack_packet(int s_fd, struct sockaddr *to, int block)
{

  /* create the maximum possible size packet that a TFTP ACK packet can be */
  char packet[TFTP_ACK_PKT_LEN];

  /* define the first two bytes of the packet */
  tftp_set_opcode(packet, TFTP_ACK);

  /* Specify the block number being ACK'd.
   * If we are ACK'ing a DATA pkt then the block number echoes that of the DATA pkt being ACK'd (duh)
   * If we are ACK'ing a WRQ pkt then the block number is always 0
   * RRQ packets are never sent ACK pkts by the server, instead the server sends DATA pkts to the
   * host which are, obviously, used as the "acknowledgement".  This saves from having to sEndTransferboth
   * an ACK packet and a DATA packet for RRQs - see RFC1350 for more info.  */
  tftp_set_block(packet, block);

  return tftp_send_message(s_fd, to, packet, TFTP_ACK_PKT_LEN);
}

/* close the file sent, disconnect and close the connection */
void tftp_cleanup_rd(tftp_connection_args *args)
{
  /* Free the tftp_connection_args structure reserverd for */
  free(args);
}

/* close the file writen, disconnect and close the connection */
void tftp_cleanup_wr(tftp_connection_args *args)
{
  /* Free the tftp_connection_args structure reserverd for */
  free(args);
}
void tftp_clean(PTFTPD args)
{
	close(args->tftp_p.c_fd);
	free(args);
}
void tftp_send_next_block(PTFTPD tftp_buf)
{
  /* Function to read 512 bytes from the file to sEndTransfer(file_SD), put them
   * in "args->data" and return the number of bytes read */
  //@@@@args->data_len = file_read(&file_SD, TFTP_DATA_LEN_MAX, (euint8*)args->data);
  int total_block = tftp_buf->tftp_p.tot_bytes/TFTP_DATA_LEN_MAX;
  total_block +=1;
  //if(args->tot_bytes%TFTP_DATA_LEN_MAX != 0)
  //{
//		total_block += 1;
  //}

  if(total_block < 1 || tftp_buf->tftp_p.block > total_block )
  {
       return;
  }

  tftp_buf->tftp_p.data_len = TFTP_DATA_LEN_MAX;
  if(total_block == tftp_buf->tftp_p.block)
  {
	   if(tftp_buf->tftp_p.tot_bytes%TFTP_DATA_LEN_MAX == 0)
	   {
	       tftp_buf->tftp_p.data_len = 0;
	   }else
	   {
	       tftp_buf->tftp_p.data_len = tftp_buf->tftp_p.tot_bytes - (total_block - 1)*TFTP_DATA_LEN_MAX;
	   }
  }
  
  memset(tftp_buf->tftp_p.data + TFTP_DATA_PKT_HDR_LEN, ('a'-1) + tftp_buf->tftp_p.block%26 , tftp_buf->tftp_p.data_len);
  /*   NOTE: We need to sEndTransferanother data packet even if args->data_len = 0
     The reason for this is as follows:
     1) This function is only ever called if the previous packet payload was
        512 bytes.
     2) If args->data_len = 0 then that means the file being sent is an exact
         multiple of 512 bytes.
     3) RFC1350 specifically states that only a payload of <= 511 can EndTransfera
        transfer.
     4) Therefore, we must sEndTransferanother data message of length 0 to complete
        the transfer.                */


  /* sEndTransferthe data */
  tftp_send_data_packet(tftp_buf->tftp_p.c_fd,(struct sockaddr *) &(tftp_buf->tftp_p.c_addr), tftp_buf->tftp_p.block, tftp_buf->tftp_p.data, tftp_buf->tftp_p.data_len);

}
#if 0
void rrq_recv_callback(void *_args, int s_fd, char *p, struct sockaddr *c_addr)
{
  /* Get our connection state  */
  tftp_connection_args *args = (tftp_connection_args *)_args;
  if(port != args->remote_port)
  {
    /* Clean the connection*/
    tftp_cleanup_rd(args);
  }
  //printf("PUT rrq_recv_callback\n");
  if (tftp_is_correct_ack(p->payload, args->block))
  {
    /* increment block # */
    args->block++;
	//printf("rrq_recv_callback ACK OK\n");
  }
  else
  {
    /* we did not receive the expected ACK, so
       do not update block #. This causes the current block to be resent. */
    //printf("rrq_recv_callback ACK UNOK\n");
  }

  /* if the last read returned less than the requested number of bytes
   * (i.e. TFTP_DATA_LEN_MAX), then we've sent the whole file and we can quit
   */
  if (args->data_len < TFTP_DATA_LEN_MAX)
  {
    /* Clean the connection*/
    tftp_cleanup_rd(upcb, args);

    pbuf_free(p);
	printf("rrq_recv_callback send over\n");
	return;
  }

  /* if the whole file has not yet been sent then continue  */
  tftp_send_next_block(upcb, args, addr, port);

  pbuf_free(p);
  //printf("rrq_recv_callback send next block\n");

}




void wrq_recv_callback(void *_args, struct udp_pcb *upcb, struct pbuf *pkt_buf, struct ip_addr *addr, u16_t port)
{
  tftp_connection_args *args = (tftp_connection_args *)_args;
  int n = 0;
  u16_t next_block = 0;
  
  if (port != args->remote_port || pkt_buf->len != pkt_buf->tot_len)
  {
    tftp_cleanup_wr(upcb, args);
    pbuf_free(pkt_buf);
    return;
  }

  next_block = args->block + 1;
  /* Does this packet have any valid data to write? */
  if ((pkt_buf->len > TFTP_DATA_PKT_HDR_LEN) &&
      (tftp_extract_block(pkt_buf->payload) == next_block))
  {
    /* write the received data to the file */
    //@@@@n = file_write(&file_CR,
    //@@@@               pkt_buf->len - TFTP_DATA_PKT_HDR_LEN,
    //@@@@               (euint8*)pkt_buf->payload + TFTP_DATA_PKT_HDR_LEN);

    //@@@@if (n <= 0)
    if(0)
    {
      tftp_send_error_message(upcb, addr, port, TFTP_ERR_FILE_NOT_FOUND);
      /* close the connection */
      tftp_cleanup_wr(upcb, args); /* close the connection */
    }

    /* update our block number to match the block number just received */
    args->block++;
    /* update total bytes  */
    (args->tot_bytes) += (pkt_buf->len - TFTP_DATA_PKT_HDR_LEN);

    /* This is a valid pkt but it has no data.  This would occur if the file being
       written is an exact multiple of 512 bytes.  In this case, the args->block
       value must still be updated, but we can skip everything else.    */
  }
  else if (tftp_extract_block(pkt_buf->payload) == next_block)
  {
    /* update our block number to match the block number just received  */
    args->block++;
  }
  else
  {
	printf("ZZZSL ERROR = %d\n" ,(args->block + 1));
  }

  /* SEndTransferthe appropriate ACK pkt (the block number sent in the ACK pkt echoes
   * the block number of the DATA pkt we just received - see RFC1350)
   * NOTE!: If the DATA pkt we received did not have the appropriate block
   * number, then the args->block (our block number) is never updated and
   * we simply sEndTransfera "duplicate ACK" which has the same block number as the
   * last ACK pkt we sent.  This lets the host know that we are still waiting
   * on block number args->block+1. */
  tftp_send_ack_packet(upcb, addr, port, args->block);

  /* If the last write returned less than the maximum TFTP data pkt length,
   * then we've received the whole file and so we can quit (this is how TFTP
   * signals the EndTransferof a transfer!)
   */
  if (pkt_buf->len < TFTP_DATA_PKT_LEN_MAX)
  {
    tftp_cleanup_wr(upcb, args);
    pbuf_free(pkt_buf);
  }
  else
  {
    pbuf_free(pkt_buf);
    return;
  }

}

int tftp_process_write(struct udp_pcb *upcb, struct ip_addr *to, int to_port, char *FileName)
{
  tftp_connection_args *args = NULL;

  /* If Could not open the file which will be transmitted  */
  //@@@@if (file_fopen(&file_CR, &efs2.myFs, FileName, 'w') != 0)
  if(0)
  {
    tftp_send_error_message(upcb, to, to_port, TFTP_ERR_FILE_ALREADY_EXISTS);

    tftp_cleanup_wr(upcb, args);

    return 0;
  }

  /* This function is called from a callback,
   * therefore interrupts are disabled,
   * therefore we can use regular malloc   */
  args = mem_malloc(sizeof(tftp_connection_args));
  if (!args)
  {
    tftp_send_error_message(upcb, to, to_port, TFTP_ERR_NOTDEFINED);

    tftp_cleanup_wr(upcb, args);

    return 0;
  }

  args->op = TFTP_WRQ;
  //args->to_ip.addr = to->addr;
  args->remote_port = to_port;
  /* the block # used as a positive response to a WRQ is _always_ 0!!! (see RFC1350)  */
  args->block = 0;
  args->tot_bytes = 0;

  /* set callback for receives on this UDP PCB (Protocol Control Block) */
  udp_recv(upcb, wrq_recv_callback, args);

  /* initiate the write transaction by sending the first ack */
  tftp_send_ack_packet(upcb, to, to_port, args->block);

  return 0;
}

#endif
int tftp_process_read(PTFTPD tftp_buf, char* FileName)
{
  /* If Could not open the file which will be transmitted  
  //@@@@if (file_fopen(&file_SD, &efs1.myFs, FileName, 'r') != 0)
  if(0)
  {
    tftp_send_error_message(upcb, to, to_port, TFTP_ERR_FILE_NOT_FOUND);

    tftp_cleanup_rd(upcb, args);

    return 0;
  }
  */


  /* initialize connection structure  */
  tftp_buf->tftp_p.op = TFTP_RRQ;

  tftp_buf->tftp_p.block = 1; /* block number starts at 1 (not 0) according to RFC1350  */
  tftp_buf->tftp_p.tot_bytes = 1024*1024;

  /* initiate the transaction by sending the first block of data
   * further blocks will be sent when ACKs are received
   *   - the receive callbacks need to get the proper state    */

  tftp_send_next_block(tftp_buf);

  return 1;
}
void process_tftp_request(char *pkt_buf, struct sockaddr_in cin, u16_t len)
{
	tftp_opcode op = tftp_decode_op(pkt_buf);
	char FileName[50] = {0};
	struct udp_pcb *upcb = NULL;
	u32_t IPaddress;
	char addr_p[INET_ADDRSTRLEN];
	PTFTPD tftp_data,tftp_tmp;
	int s_fd;
	struct sockaddr_in sin;
	inet_ntop(AF_INET, &cin.sin_addr, addr_p, sizeof(addr_p));
	printf("TFTP RRQ from: %s, port is %d\n",addr_p, ntohs(cin.sin_port));
	printf("client msg is:%s", pkt_buf); 	
	tftp_data = (PTFTPD *)malloc(sizeof(TFTPD));
	if(tftp_data == NULL)
	{
		printf("can not malloc tftp\n");
		return 0;
	}
	tftp_data->next = NULL;
	tftp_data->tftp_p.c_addr = cin;

	// insert client 
	if(client_head.next == NULL)
	{
		client_head.next = tftp_data;
	}
	else
	{
		tftp_tmp = &client_head;
		while(tftp_tmp->next != NULL)
		{
			tftp_tmp = tftp_tmp->next;
		}
		tftp_tmp->next = tftp_data;
	}
	//bind local port
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(TFTP_PORT + 100);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	s_fd = socket(AF_INET, SOCK_DGRAM, 0);  //创建套接字

	if(s_fd < 0)
	{
		printf("can not creat socket\r\n");
		return -1;
	}

	if(bind(s_fd, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1)
	{
		printf("can't bind\r\n");
		return -1;
	}

	tftp_data->tftp_p.local_port = sin.sin_port;
	tftp_data->tftp_p.c_fd = s_fd;
	if(s_fd > max_fd)
	{
		max_fd = s_fd;
	}
	FD_SET(s_fd, &read_set); //add s_fd to select
  tftp_extract_filename(FileName, pkt_buf);

  switch (op)
  {

    case TFTP_RRQ:    /* TFTP RRQ (read request)  */
      /* Read the name of the file asked by the client 
                            to be sent from the SD card */
      /* Start the TFTP read mode*/
      printf("\n\rTFTP client start to read file..[%s]..", FileName);
	  tftp_process_read(tftp_data, FileName);
      break;

    case TFTP_WRQ:    /* TFTP WRQ (write request)   */
      /* Read the name of the file asked by the client 
                to received and writen in the SD card */
      //tftp_extract_filename(FileName, pkt_buf->payload);

      /* If Could not open filesystem */
      //@@@@if (efs_init(&efs2, 0) != 0)
      if(0)
      {
        return;
      }
      /* If Could not open the selected directory */
      //@@@@if (ls_openDir(&list2, &(efs2.myFs), "/") != 0)
      if(0)
      {
        return;
      }
	  printf("\n\rTFTP client start to write file..[%s]..", FileName);

      /* Start the TFTP write mode*/
//      tftp_process_write(upcb, addr, port, FileName);
      break;

    default:
      /* sEndTransfera generic access violation message */
 //     tftp_send_error_message(tftp_data, TFTP_ERR_ACCESS_VIOLATION);
      /* TFTP unknown request op */
      /* no need to use tftp_cleanup_wr because no 
            "tftp_connection_args" struct has been malloc'd   */
 //     udp_remove(upcb);
	tftp_clean(tftp_data);
 	printf("error msg\r\n");

      break;
  }
}
int  tftp_server_init(int *s_fd, struct sockaddr *sin)
{
	*s_fd = socket(AF_INET, SOCK_DGRAM, 0);  //创建套接字

	if(*s_fd < 0)
	{
		printf("can not creat socket\r\n");
		return -1;
	}

	if(bind(*s_fd, sin, sizeof(*sin)) == -1)
	{
		printf("can't bind\r\n");
		return -1;
	}
	return 0;
}

int main()
{

	struct sockaddr_in sin,cin;
	int s_fd;
	socklen_t addr_len;
	char buf[MAX_LINE];
	char addr_p[INET_ADDRSTRLEN];  //ip地址的存放缓冲区
	int n;
	struct timeval tv;
	int res_sel;
	PTFTPD tftp_tmp;
	
	client_head.next = NULL;

	FD_ZERO(&read_set);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(TFTP_PORT);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	tftp_server_init(&s_fd, (struct sockaddr *)&sin); 
	FD_SET(s_fd, &read_set);
	tv.tv_sec  = 3;
	tv.tv_usec = 0;
	max_fd = s_fd;
	printf("s_fd : %d\r\n",s_fd);
	while(1)
	{
		addr_len = sizeof(sin);		
		res_sel = select(max_fd + 1, &read_set, NULL, NULL, NULL/*&tv*/);
		if(res_sel == 0)
		{
			//printf("select timeout\n");
		}
		else
		{
			if(FD_ISSET(s_fd, &read_set))  //
			{
				n = recvfrom(s_fd, buf, MAX_LINE, 0, (struct sockaddr*)&cin, &addr_len);
				if(n == -1)
				{
					printf("fail to recvfrom msg\r\n");
				}
				else
				{	
					process_tftp_request(buf, cin, addr_len);
				}	
			}
			tftp_tmp = &client_head;
			while(tftp_tmp->next != NULL)
			{
				tftp_tmp = tftp_tmp->next;
				if(FD_ISSET(tftp_tmp->tftp_p.c_fd, &read_set))  //
				{
					//rrq_recv_callback();
					printf("client msg\r\n");
				}
			}
		}

/*
		my_fun(buf);
		n = sendto(s_fd, buf, n, 0, (struct sockaddr *)&cin, addr_len);
		if(n == -1)
		{
			printf("fail to send\n");
			break;
		}
*/
	}
	if(close(s_fd) == -1)
	{
		printf("fail to close socket\n");
	}
	
	tftp_tmp = &client_head;
	while(tftp_tmp->next != NULL)
	{
		tftp_tmp = tftp_tmp->next;
		tftp_clean(tftp_tmp);
	}
	return 0; 
}
