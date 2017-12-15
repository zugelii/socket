#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#define MAX_LINE 100
void my_fun(char *p)
{
	if(p == NULL)
		return;
	else
	{
		for(; *p != '\0'; p++)
		{
			if(*p > 'A' && *p < 'Z')
				*p = *p - 'A' +  'a';
		}
	}
}

int main()
{
	struct sockaddr_in sin,cin;
	int s_fd;
	int port = 3000;
	socklen_t addr_len;
	char buf[MAX_LINE];
	char addr_p[INET_ADDRSTRLEN];  //ip地址的存放缓冲区
	int n, flags;
	printf("INET_ADDRSTRLEN:%d\n", INET_ADDRSTRLEN);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);

	s_fd = socket(AF_INET, SOCK_DGRAM, 0);  //创建套接字

	if(s_fd < 0)
	{
		printf("can not creat socket\r\n");
		return 0;
	}

	flags = fcntl(s_fd, F_GETFL);
	flags |= O_NONBLOCK;//set socket to no block

	if(fcntl(s_fd, F_SETFL, flags) == -1)
	{
		printf("fcntl error\r\n");
		return 0;
	}




	if(bind(s_fd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
	{
		printf("can't bind\r\n");
		return 0;
	}

	while(1)
	{
		sleep(5);
		addr_len = sizeof(sin);
		n = recvfrom(s_fd, buf, MAX_LINE, 0, (struct sockaddr*)&cin, &addr_len);
		if(n == -1 && errno != EAGAIN)
		{
			printf("fail to recev msg\n");
			break;
		}
		else if (errno == EAGAIN)
		{
			/* code */
			printf("socket are not ready now\n");
		}
		inet_ntop(AF_INET, &cin.sin_addr, addr_p, sizeof(addr_p));//将客户端IP地址转换为字符串
		printf("client IP is %s, port is %d\n",addr_p, ntohs(cin.sin_port));
		printf("client msg is:%s", buf); //客户端的消息
		my_fun(buf);
		n = sendto(s_fd, buf, n, 0, (struct sockaddr *)&cin, addr_len);
		if(n == -1 && errno != EAGAIN)
		{
			printf("fail to send\n");
			break;
		}
		else if (errno == EAGAIN)
		{
			/* code */
			printf("socket are not ready now\n");
		}

	}
	if(close(s_fd) == -1)
	{
		printf("fail to close socket\n");
	}
	return 0;
}
