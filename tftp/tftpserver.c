#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include "tftp.h"
#include <errno.h>
#include <sys/select.h>
#define MAX_LINE 100

typedef unsigned   char    u8_t;
typedef signed     char    s8_t;
typedef unsigned   short   u16_t;
typedef signed     short   s16_t;
typedef unsigned   int    u32_t;
typedef signed     int    s32_t;


#define MFS_MODE_READ 0
#define MFS_MODE_WRITE 1

#define TFTP_OPCODE_LEN         2
#define TFTP_BLKNUM_LEN         2
#define TFTP_ERRCODE_LEN        2
#define TFTP_DATA_LEN_MAX       512
#define TFTP_DATA_PKT_HDR_LEN   (TFTP_OPCODE_LEN + TFTP_BLKNUM_LEN)
#define TFTP_ERR_PKT_HDR_LEN    (TFTP_OPCODE_LEN + TFTP_ERRCODE_LEN)
#define TFTP_ACK_PKT_LEN        (TFTP_OPCODE_LEN + TFTP_BLKNUM_LEN)
#define TFTP_DATA_PKT_LEN_MAX   (TFTP_DATA_PKT_HDR_LEN + TFTP_DATA_LEN_MAX)
#define TFTP_MAX_RETRIES        3
#define TFTP_TIMEOUT_INTERVAL   5

/* TFTP opcodes as specified in RFC1350   */
typedef enum {
  TFTP_RRQ = 1,
  TFTP_WRQ = 2,
  TFTP_DATA = 3,
  TFTP_ACK = 4,
  TFTP_ERROR = 5
} tftp_opcode;


/* TFTP error codes as specified in RFC1350  */
typedef enum {
  TFTP_ERR_NOTDEFINED,
  TFTP_ERR_FILE_NOT_FOUND,
  TFTP_ERR_ACCESS_VIOLATION,
  TFTP_ERR_DISKFULL,
  TFTP_ERR_ILLEGALOP,
  TFTP_ERR_UKNOWN_TRANSFER_ID,
  TFTP_ERR_FILE_ALREADY_EXISTS,
  TFTP_ERR_NO_SUCH_USER,
} tftp_errorcode;



typedef struct
{
  int op;    /* RRQ/WRQ */

  /* last block read */
  char data[TFTP_DATA_PKT_LEN_MAX];
  int  data_len;
  
  

  /* next block number */
  u16_t block;

  /* total number of bytes transferred */
  u32_t tot_bytes;
  int c_fd; //
  u16_t remote_port;
  struct sockaddr c_addr;
}tftp_connection_args;

typedef struct tftp_data
{
	tftp_connection_args tftp_p;
	tftp_data *next;
}TFTPD,*PTFTPD;

fd_set read_set,write_set;
PTFTPD client_head;
#if 0
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
	n = sendto(s_fd, buf_loc, n, 0, addr, sizeof(struct sockaddr));
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
int tftp_send_data_packet(int s_fd, struct sockaddr *to, int block, char *buf, int buflen)
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

void tftp_send_next_block(int s_fd, tftp_connection_args *args, struct sockaddr *to_addr)
{
  /* Function to read 512 bytes from the file to sEndTransfer(file_SD), put them
   * in "args->data" and return the number of bytes read */
  //@@@@args->data_len = file_read(&file_SD, TFTP_DATA_LEN_MAX, (euint8*)args->data);
  int total_block = args->tot_bytes/TFTP_DATA_LEN_MAX;
  total_block +=1;
  //if(args->tot_bytes%TFTP_DATA_LEN_MAX != 0)
  //{
//		total_block += 1;
  //}

  if(total_block < 1 || args->block > total_block )
  {
       return;
  }

  args->data_len = TFTP_DATA_LEN_MAX;
  if(total_block == args->block)
  {
	   if(args->tot_bytes%TFTP_DATA_LEN_MAX == 0)
	   {
	       args->data_len = 0;
	   }else
	   {
	       args->data_len = args->tot_bytes - (total_block - 1)*TFTP_DATA_LEN_MAX;
	   }
  }
  
  memset(args->data + TFTP_DATA_PKT_HDR_LEN, ('a'-1) + args->block%26 , args->data_len);
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
  tftp_send_data_packet(s_fd, to_addr, args->block, args->data, args->data_len);

}
#if 0
void rrq_recv_callback(void *_args, int s_fd, struct pbuf *p, struct sockaddr *c_addr)
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

int tftp_process_read(struct udp_pcb *upcb, struct ip_addr *to, int to_port, char* FileName)
{
  tftp_connection_args *args = NULL;

  /* If Could not open the file which will be transmitted  */
  //@@@@if (file_fopen(&file_SD, &efs1.myFs, FileName, 'r') != 0)
  if(0)
  {
    tftp_send_error_message(upcb, to, to_port, TFTP_ERR_FILE_NOT_FOUND);

    tftp_cleanup_rd(upcb, args);

    return 0;
  }

  /* This function is called from a callback,
   * therefore, interrupts are disabled,
   * therefore, we can use regular malloc. */

  args = mem_malloc(sizeof(tftp_connection_args));
  /* If we aren't able to allocate memory for a "tftp_connection_args" */
  if (!args)
  {
    /* unable to allocate memory for tftp args  */
    tftp_send_error_message(to, to_port, TFTP_ERR_NOTDEFINED);

    /* no need to use tftp_cleanup_rd because no 
            "tftp_connection_args" struct has been malloc'd   */
    tftp_cleanup_rd(upcb, args);

    return 0;
  }

  /* initialize connection structure  */
  args->op = TFTP_RRQ;
  //args->to_ip.addr = to->addr;
  args->remote_port = to_port;
  args->block = 1; /* block number starts at 1 (not 0) according to RFC1350  */
  args->tot_bytes = 1024*1024;


  /* set callback for receives on this UDP PCB (Protocol Control Block) */
  udp_recv(upcb, rrq_recv_callback, args);

  /* initiate the transaction by sending the first block of data
   * further blocks will be sent when ACKs are received
   *   - the receive callbacks need to get the proper state    */

  tftp_send_next_block(upcb, args, to, to_port);

  return 1;
}
#endif
#if 0
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

#endif
tftp_connection_args *tftp_quene;
void process_tftp_request(char *pkt_buf, struct sockaddr *cin, u16_t len)
{
  tftp_opcode op = tftp_decode_op(pkt_buf->payload);
  char FileName[50] = {0};
  struct udp_pcb *upcb = NULL;
  err_t err;
  u32_t IPaddress;
  char addr_p[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, (struct sockaddr*)cin->sin_addr, addr_p, sizeof(addr_p));//将客户端IP地址转换为字符串
  printf("TFTP RRQ from: %s, port is %d\n",addr_p, ntohs((struct sockaddr*)cin->sin_port));
  printf("client msg is:%s", buf); //客户端的消息	
  PTFTPD tftp_buf = (PTFTPD *)malloc(sizeof(TFTPD));
  if(tftp_buf == NULL)
  {
  	printf("can not malloc tftp\n");
  	return 0;
  }
  tftp_buf->next = NULL;
  tftp_buf->
  tftp_extract_filename(FileName, pkt_buf->payload);

  switch (op)
  {

    case TFTP_RRQ:    /* TFTP RRQ (read request)  */
      /* Read the name of the file asked by the client 
                            to be sent from the SD card */
      //tftp_extract_filename(FileName, pkt_buf->payload);

      //printf("\n\rTFTP RRQ (read request)");
      //printf("\n\rONLY EFS filesystem(NTFS in WinXp) is support");
      
      /* If Could not open filesystem */
      //@@@@if (efs_init(&efs1, 0) != 0)
      //@@@@{
      //@@@@printf("\n\rIf Could not open filesystem");
      //@@@@return;
      //@@@@}
      
      /* If Could not open the selected directory */
      //@@@@if (ls_openDir(&list1, &(efs1.myFs), "/") != 0)
      //@@@@{
      //@@@@  printf("\n\rIf Could not open the selected directory");
      //@@@@  return;
      //@@@@}
      /* Start the TFTP read mode*/
      printf("\n\rTFTP client start to read file..[%s]..", FileName);
      tftp_process_read(upcb, addr, port, FileName);
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
      tftp_process_write(upcb, addr, port, FileName);
      break;

    default:
      /* sEndTransfera generic access violation message */
      tftp_send_error_message(upcb, addr, port, TFTP_ERR_ACCESS_VIOLATION);
      /* TFTP unknown request op */
      /* no need to use tftp_cleanup_wr because no 
            "tftp_connection_args" struct has been malloc'd   */
      udp_remove(upcb);

      break;
  }
}


#define TFTP_PORT 8000
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
	int max_fd;
	struct timeval tv;
	int res_sel;

	client_head = (PTFTPD)malloc(sizeof(TFTPD));
	client_head->next = NULL;

	FD_ZERO(&read_set);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(8000);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	tftp_server_init(&s_fd, (struct sockaddr *)&sin) 
	FD_SET(s_fd, &read_set);
	tv.tv_sec  = 3;
	tv.tv_usec = 0;
	max_fd = s_fd;

	while(1)
	{
		addr_len = sizeof(sin);		
		res_sel = select(max_fd + 1, &read_set, NULL, NULL, &tv);
		if(res_sel == 0)
		{
			printf("select timeout\n");
		}
		else
		{
			if(FD_ISSET(s_fd, &read_set))  //客户机请求接入
			{
				n = recvfrom(s_fd, buf, MAX_LINE, 0, (struct sockaddr*)&cin, &addr_len);
				if(n == -1)
				{
					printf("fail to recvfrom msg\r\n");
				}
				else
				{	
					process_tftp_request(buf, (struct sockaddr*)&cin, addr_len);
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
	return 0; 
}
