#include "ping.h"

#define PINGPACKETBUF 128

typedef struct pingm_packet{
	struct timeval tv_begin;
	struct timeval tv_end;
	short seq;
	int flag;
}pingm_packet;

pingm_packet pingpacket[PINGPACKETBUF];
pingm_packet *icmp_findpacket(int seq);
void tv_sub(struct timeval *out, struct timeval *in);
u_short in_cksum(u_short *addr, int len);
void icmp_statistics(void);
void icmp_pack(struct icmp *icmph, int seq, struct timeval *tv, int length);
int icmp_unpack(char *buf,int len);
void *icmp_recv(void *argv);
void *icmp_send(void *argv);
void icmp_sigint(int signo);
void icmp_usage();
#define K 1024
#define BUFFERSIZE 72
char send_buff[BUFFERSIZE];
char recv_buff[2*K];
int rawsock = 0;
pid_t pid=0;
int alive = 0;
short packet_send = 0;
short packet_recv = 0;
struct addrinfo *dest_addr;
struct timeval tv_begin, tv_end,tv_interval;
struct addrinfo *Host_serv(const char *host, const char *serv, int family, int socktype);
void icmp_usage();
typedef void (* signalHandler) (int sig);
void set_signal_handler(int sig, signalHandler handler);
void icmp_sigint(int signo);

int main(int argc, char **argv)
{
	struct protoent *protocol = NULL;
	int size = 128 * K;
	pthread_t send_id, recv_id;
	int err = 0;;
	int c;
	
	opterr = 0;
	while( (c = getopt(argc, argv, "v")) != -1)
	{
		switch(c)
		{
			case 'v':
				verbose++;
				break;
			case '?':
				fprintf(stderr, "unrecofnized option: %c\n", c);
				break;
		}
	}
	if(optind != argc - 1)
	{
		fprintf(stderr, "usage: ping [ -v ] <hostname>\n");
		return -1;
	}
	host = argv[optind];

	dest_addr = Host_serv(host, NULL, AF_INET, SOCK_RAW);
	if(NULL == dest_addr)
	{
		return -1;
	}
	protocol = getprotobyname("icmp");
	if(protocol == NULL)
	{
		fprintf(stderr, "getprotobyname error: %s\n", strerror(errno));
		return -1;
	}

	rawsock = socket(dest_addr->ai_family, dest_addr->ai_socktype, protocol->p_proto);
	if(rawsock < 0)
	{
		fprintf(stderr, "socket error: %s\n", strerror(errno));
		return -1;
	}

	pid = getpid() & 0xffff;

	setsockopt(rawsock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

	set_signal_handler(SIGINT, icmp_sigint);
	alive = 1;

	err = pthread_create(&send_id, NULL, icmp_send, NULL);
	if(err < 0)
	{
		return -1;
	}
	err = pthread_create(&recv_id, NULL, icmp_recv, NULL);
	if(err < 0)
	{
		return -1;
	}

	pthread_join(send_id, NULL);
	pthread_join(recv_id, NULL);
	close(rawsock);
	icmp_statistics();
	return 0;
}




void icmp_sigint(int signo)
{
	alive = 0;
	gettimeofday(&tv_end, NULL);
	tv_sub(&tv_end, &tv_begin);
	tv_interval = tv_end;
	return;
}


void set_signal_handler(int sig, signalHandler handler)
{
	struct sigaction act;
	sigset_t empty_mask;
	memset(&act, 0, sizeof(act));
	sigemptyset(&empty_mask);
	act.sa_handler = handler;
	act.sa_mask = empty_mask;
	act.sa_flags = 0;
	sigaction(sig, &act, NULL);
	return;
}



/*Just copy first one*/
struct addrinfo *addrInfoDup(struct addrinfo *srcInfo)
{
	struct addrinfo *destInfo;
	if(NULL == srcInfo)
		return NULL;
	destInfo = (struct addrinfo *)malloc(sizeof(struct addrinfo));
	if(destInfo == NULL)
		return NULL;
#define ADDR_INFO_COPY(ITEM) \
	destInfo->ITEM = srcInfo->ITEM

	ADDR_INFO_COPY(ai_flags);
	ADDR_INFO_COPY(ai_family);
	ADDR_INFO_COPY(ai_socktype);
	ADDR_INFO_COPY(ai_protocol);
	ADDR_INFO_COPY(ai_addrlen);
	destInfo->ai_canonname = NULL;
	destInfo->ai_next = NULL;
	switch(srcInfo->ai_family)
	{
		case AF_INET:
			destInfo->ai_addr = (struct sockaddr *)malloc(sizeof(struct sockaddr_in));
			assert(destInfo->ai_addr != NULL);
			memcpy(destInfo->ai_addr, srcInfo->ai_addr, sizeof(struct sockaddr_in));
			break;
		case AF_INET6:
			destInfo->ai_addr = (struct sockaddr *)malloc(sizeof(struct sockaddr_in6));
			assert(destInfo->ai_addr != NULL);
			memcpy(destInfo->ai_addr, srcInfo->ai_addr, sizeof(struct sockaddr_in6));
			break;
		default:
			free(destInfo);
			return NULL;
			
	}
	return destInfo;
}

void addrInfoFree(struct addrinfo *srcInfo)
{
	if(srcInfo == NULL)
	{
		return;
	}
	if(srcInfo->ai_addr != NULL)
	{
		free(srcInfo->ai_addr);
		srcInfo->ai_addr = NULL;
	}
	free(srcInfo);
	srcInfo = NULL;
	return;
}
struct addrinfo *Host_serv(const char *host, const char *serv, int family, int socktype)
{
	int n;
	struct addrinfo hints, *res;
	struct addrinfo *addr;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = family; /*AF_UNSPEC AF_INET AF_INET6*/
	hints.ai_flags = AI_CANONNAME;
	hints.ai_socktype = socktype;

	if( (n = getaddrinfo(host, serv, &hints, &res)) != 0)
	{
		fprintf(stderr, "host_serv error : %s\n", gai_strerror(n));
		return NULL;
	}
#if 0
	addr = (struct addrinfo *)malloc(sizeof(struct addrinfo));
	memcpy(addr, res, sizeof(struct addrinfo));
#endif
	addr = addrInfoDup(res);
	freeaddrinfo(res);
	return addr;
}


void tv_sub(struct timeval *out, struct timeval *in)
{
	if( (out->tv_usec -= in->tv_usec) < 0 )
	{
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}
u_short in_cksum(u_short *addr, int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}
	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;						
	}

	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

void icmp_usage()
{
	fprintf(stderr, "usage: ping [ -v ] <hostname>\n");
	return;
}

void icmp_statistics(void)
{       
	long time = (tv_interval.tv_sec * 1000 )+ (tv_interval.tv_usec/1000);
	char dst[128] = "";
	if(NULL != inet_ntop(AF_INET, &((struct sockaddr_in *)dest_addr->ai_addr)->sin_addr, dst, sizeof(dst)))
	{
		printf("--- %s ping statistics ---\n", dst);	/*目的IP地址*/
		printf("%d packets transmitted, %d received, %d%% packet loss, time %ldms\n",
			packet_send,									/*发送*/
			packet_recv,  									/*接收*/
			(packet_send-packet_recv)*100/packet_send, 	/*丢失百分比*/
			time); 											/*时间*/
	}
}
void* icmp_send(void *argv)
{
	/*保存程序开始发送数据的时间*/
	gettimeofday(&tv_begin, NULL);
	while(alive)
	{
		int size = 0;
		struct timeval tv;
		gettimeofday(&tv, NULL);			/*当前包的发送时间*/
		/*在发送包状态数组中找一个空闲位置*/
		pingm_packet *packet = icmp_findpacket(-1);
		if(packet)
		{
			packet->seq = packet_send;		/*设置seq*/
			packet->flag = 1;			/*已经使用*/
			gettimeofday( &packet->tv_begin, NULL);	/*发送时间*/
		}
		
		icmp_pack((struct icmp *)send_buff, packet_send, &tv, sizeof(send_buff) );
		/*打包数据*/
		size = sendto (rawsock,  send_buff, sizeof(send_buff),  0,		/*发送给目的地址*/
			(struct sockaddr *)dest_addr->ai_addr, sizeof(*dest_addr->ai_addr) );
		if(size <0)
		{
			perror("sendto error");
			continue;
		}
		packet_send++;					/*计数增加*/
		/*每隔1s，发送一个ICMP回显请求包*/
		sleep(1);
	}
}
void icmp_pack(struct icmp *icmph, int seq, struct timeval *tv, int length )
{
	unsigned char i = 0;
	/*设置报头*/
	icmph->icmp_type = ICMP_ECHO;	/*ICMP回显请求*/
	icmph->icmp_code = 0;			/*code值为0*/
	icmph->icmp_cksum = 0;	  /*先将cksum值填写0，便于之后的cksum计算*/
	icmph->icmp_seq = seq;			/*本报的序列号*/
	icmph->icmp_id = pid &0xffff;	/*填写PID*/
	for(i = 0; i< length; i++)
		icmph->icmp_data[i] = i;
									/*计算校验和*/
	icmph->icmp_cksum = in_cksum((u_short *)icmph, length);
}
void *icmp_recv(void *argv)
{
	/*轮询等待时间*/
	struct timeval tv;
	tv.tv_usec = 200;
	tv.tv_sec = 0;
	fd_set  readfd;
	/*当没有信号发出一直接收数据*/
	while(alive)
	{
		int ret = 0;
		FD_ZERO(&readfd);
		FD_SET(rawsock, &readfd);
		ret = select(rawsock+1,&readfd, NULL, NULL, &tv);
		switch(ret)
		{
			case -1:
				/*错误发生*/
				break;
			case 0:
				/*超时*/
				break;
			default:
			{
				/*接收数据*/
				int size = recv(rawsock, recv_buff,sizeof(recv_buff), 0);
				if(errno == EINTR)
				{
					perror("recvfrom error");
					continue;
				}
				/*解包，并设置相关变量*/
				ret = icmp_unpack(recv_buff, size);
				if(ret == -1)
				{
					continue;
				}
			}
			break;
		}
		
	}
}

int icmp_unpack(char *buf,int len)
{
	int iphdrlen;
	struct ip *ip = NULL;
	struct icmp *icmp = NULL;
	int rtt;
	
	ip=(struct ip *)buf; 					/*IP头部*/
	iphdrlen=ip->ip_hl*4;					/*IP头部长度*/
	icmp=(struct icmp *)(buf+iphdrlen);		/*ICMP段的地址*/
	len-=iphdrlen;
											/*判断长度是否为ICMP包*/
	if( len<8) 
	{
		printf("ICMP packets\'s length is less than 8\n");
		return -1;
	}
	/*ICMP类型为ICMP_ECHOREPLY并且为本进程的PID*/
	if( (icmp->icmp_type==ICMP_ECHOREPLY) && (icmp->icmp_id== pid) )	
	{
		struct timeval tv_internel,tv_recv,tv_send;
		/*在发送表格中查找已经发送的包，按照seq*/
		pingm_packet* packet = icmp_findpacket(icmp->icmp_seq);
		if(packet == NULL)
			return -1;
		packet->flag = 0;	/*取消标志*/
		tv_send = packet->tv_begin;			/*获取本包的发送时间*/
		gettimeofday(&tv_recv, NULL);		/*读取此时间，计算时间差*/
		tv_sub(&tv_recv, &tv_send);
		tv_internel = tv_recv;
		rtt = tv_internel.tv_sec*1000+tv_internel.tv_usec/1000; 
		/*打印结果，包含
		*  ICMP段长度
		*  源IP地址
		*  包的序列号
		*  TTL
		*  时间差
		*/
		printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%d ms\n",
			len,
			inet_ntoa(ip->ip_src),
			icmp->icmp_seq,
			ip->ip_ttl,
			rtt);
		
		packet_recv ++;						/*接收包数量加1*/
	}
	else
	{
		return -1;
	}
	return 0;
}

pingm_packet *icmp_findpacket(int seq)
{
	int i=0;
	pingm_packet *found = NULL;
	/*查找包的位置*/
	if(seq == -1)							/*查找空包的位置*/
	{
		for(i = 0;i<128;i++)
		{
			if(pingpacket[i].flag == 0)
			{
				found = &pingpacket[i];
				break;
			}
			
		}
	}
	else if(seq >= 0)						/*查找对应seq的包*/
	{
		for(i = 0;i<128;i++)
		{
			if(pingpacket[i].seq == seq)
			{
				found = &pingpacket[i];
				break;
			}
			
		}
	}
	return found;
}
