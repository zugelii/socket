#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define BUF_LEN 512
#define SERVER_PORT 8000
#define SERVER_IP "127.0.0.1"

void upd_msg_sender(int fd, struct sockaddr* dst)
{
	socklen_t len;
	struct sockaddr_in src;
	char addrp[INET_ADDRSTRLEN];
	while(1)
	{
		char buf[BUF_LEN] = "test udp msg\n";
		len = sizeof(*dst);
		printf("client send:%s\n", buf);
		sendto(fd, buf, BUF_LEN, 0, dst, len);
		memset(buf, 0, BUF_LEN);
		recvfrom(fd, buf, BUF_LEN, 0, (struct sockaddr *)&src, &len); //接受来自SERVER的msg
		inet_ntop(AF_INET, &src.sin_addr, addrp, sizeof(addrp));
		printf("server IP:%s  port:%d send:%s\n", addrp, ntohs(src.sin_port), buf);
		sleep(1);
	}
}

int main()
{
	int client_fd;
	struct sockaddr_in ser_addr;
	client_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(client_fd < 0)
	{
		printf("create socket failed\n");
		return 0;
	}

	memset(&ser_addr, 0, sizeof(ser_addr));
	ser_addr.sin_family = AF_INET;
	ser_addr.sin_port = htons(SERVER_PORT);
	//ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	ser_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
	printf("s_addr:%d\r\n", ser_addr.sin_addr.s_addr);
	upd_msg_sender(client_fd,(struct sockaddr*)&ser_addr);

	close(client_fd);
	return 0;
}