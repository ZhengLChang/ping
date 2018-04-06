#include "ping.h"

struct proto proto_v4 = {proc_v4, send_v4, NULL, NULL, 0, IPPROTO_ICMP};

int datalen = 56;

typedef void (* signalHandler) (int sig);
char* network_get_host_ip(char *buf, int buf_size);
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

void sig_alrm(int signo)
{
	(*pr->fsend)();
	alarm(1);
	return;
}

void readloop(void)
{
	int size;
	char recvbuf[BUFSIZE];
	char controlbuf[BUFSIZE];
	struct msghdr msg;
	struct iovec iov;
	ssize_t n;
	struct timeval tval;
	const int on = 1;

	fprintf(stderr, "%s %d, family %d, icmp proto: %d\n", __func__, __LINE__, pr->sasend->sa_family, pr->icmpproto);
	if((sockfd = socket(pr->sasend->sa_family, SOCK_RAW, IPPROTO_ICMP)) < 0)
	{
		fprintf(stderr, "%s %d, %s\n", __func__, __LINE__, strerror(errno));
		return ;
	}
	if(pr->finit)
		(*pr->finit)();
	size = 60 * 1024;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
#if 1
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		fprintf(stderr, "setsockopt error: %s\n", strerror(errno));
		return;
	}
#endif
	sig_alrm(SIGALRM);
	
	iov.iov_base = recvbuf;
	iov.iov_len = sizeof(recvbuf);
	msg.msg_name = pr->sarecv;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = controlbuf;
	for(;;)
	{
		msg.msg_namelen = pr->salen;
		msg.msg_controllen = sizeof(controlbuf);
		n = recvmsg(sockfd, &msg, 0);
		if(n < 0)
		{
			if(errno == EINTR)
				continue;
			else
			{
				fprintf(stderr, "%s %d, %s\n", __func__, __LINE__, strerror(errno));
				return;
			}
		}
		gettimeofday(&tval, NULL);
		(*pr->fproc)(recvbuf, n, &msg, &tval);
	}
}

struct addrinfo *Host_serv(const char *host, const char *serv, int family, int socktype)
{
	int n;
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = family;
	hints.ai_socktype = socktype;

	if( (n = getaddrinfo(host, serv, &hints, &res)) != 0)
	{
		fprintf(stderr, "host_serv error : %s\n", gai_strerror(n));
		return NULL;
	}
	return res;
}

int main(int argc, char **argv)
{
	int c;
	struct addrinfo *ai;

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
	pid = getpid() & 0xffff;
	set_signal_handler(SIGALRM, sig_alrm);	
	
	ai = Host_serv(host, NULL, 0, 0);
	
	if(ai->ai_family == AF_INET)
	{
		pr = &proto_v4;
	}
	else
	{
		fprintf(stderr, "unkown address family %d\n", ai->ai_family);
	}
	pr->sasend = ai->ai_addr;
	pr->sarecv = calloc(1, ai->ai_addrlen);
	pr->salen = ai->ai_addrlen;
	
	readloop();	
	return 0;
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

void proc_v4(char *ptr, ssize_t len, struct msghdr *msg, struct timeval *tvrecv)
{
	int hlen1, icmplen;
	double rtt;
	struct ip *ip;
	struct icmp *icmp;
	struct timeval *tvsend;
	char str[128];

	ip = (struct ip *)ptr;
	hlen1 = ip->ip_hl << 2;

	switch(ip->ip_p)
	{
		case IPPROTO_TCP:
			fprintf(stderr, "get tcp protocol\n");
			return;
			break;
		case IPPROTO_UDP:
			fprintf(stderr, "get udp protocol\n");
			return;
			break;
	}
	/*
	if(ip->ip_p != IPPROTO_ICMP)
	{
		return;
	}
	*/
	icmp = (struct icmp *)(ptr + hlen1);
	if( (icmplen = len - hlen1) < 8)
		return;
	if(icmp->icmp_type == ICMP_ECHOREPLY)
	{
		if(icmp->icmp_id != pid)
			return;
		if(icmplen < 16)
			return;
		tvsend = (struct timeval *)icmp->icmp_data;
		tv_sub(tvrecv, tvsend);

		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

		if( NULL == inet_ntop(pr->sarecv->sa_family, (void *)(&((struct sockaddr_in *)pr->sarecv)->sin_addr), str, sizeof(str)) )
		{
			fprintf(stderr, "%s %d, inet_ntop error: %s\n", __func__, __LINE__, strerror(errno));
			return ;
		}
		fprintf(stderr, "%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
				icmplen, str, icmp->icmp_seq, ip->ip_ttl, rtt);
	}
	else
	{
		if( NULL == inet_ntop(pr->sarecv->sa_family, &((struct sockaddr_in *)pr->sarecv)->sin_addr, str, sizeof(str)) )
		{
			fprintf(stderr, "%s %d, inet_ntop error: %s\n", __func__, __LINE__, strerror(errno));
			return ;
		}
		fprintf(stderr, "%d bytes from %s: type = %d, code = %d\n",
				icmplen, str, icmp->icmp_type, icmp->icmp_code);
	}

	return ;
}

u_short in_cksum(addr, len)
	u_short *addr;
	int len;
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
void send_v4(void)
{
	int len = 0;
	struct icmp *icmp;
	struct ip *ip;
	char host_ip[64];

	memset(sendbuf, 0, sizeof(sendbuf));

	ip = (struct ip*)sendbuf;
	ip->ip_v = IPVERSION;
	ip->ip_hl = sizeof(struct ip) >> 2;
	ip->ip_tos = 0;
	ip->ip_len = 0; /*temporary*/
	ip->ip_id = pid;
	ip->ip_off = 0;
	ip->ip_ttl = MAXTTL;
	ip->ip_p = IPPROTO_ICMP;
	ip->ip_sum = 0;
	inet_pton(AF_INET, network_get_host_ip(host_ip, sizeof(host_ip)), &ip->ip_src);
	ip->ip_dst = ((struct sockaddr_in *)pr->sasend)->sin_addr;
#if 1
	icmp = /*(struct icmp *)sendbuf*/(struct icmp *)(sendbuf + sizeof(struct ip));
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_id = pid;
	icmp->icmp_seq = nsent++;
	memset(icmp->icmp_data, 0xa5, datalen);

	gettimeofday((struct timeval *)icmp->icmp_data, NULL);

	len = 8 + datalen;

	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum((u_short *) icmp, len); 
#endif
#if 1
	ip->ip_len = sizeof(struct ip) + len;
	ip->ip_sum = in_cksum(( u_short*) ip, sizeof(struct ip));
#endif

	sendto(sockfd, sendbuf, sizeof(struct ip) + len, 0, pr->sasend, pr->salen);
	return;
}

char* network_get_host_ip(char *buf, int buf_size) {
	struct ifaddrs *ifaddr, *ifa;

	if(getifaddrs(&ifaddr) == -1)
	{
		fprintf(stderr, "getifaddrs error: %s\n", strerror(errno));
		return NULL;
	}
	for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if(ifa->ifa_addr == NULL)
			continue;
		if(strncmp(ifa->ifa_name, "eth", sizeof("eth") - 1) == 0 && 
				ifa->ifa_addr->sa_family == AF_INET)
		{
			if(NULL == inet_ntop(ifa->ifa_addr->sa_family, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, buf, buf_size))
			{
				continue;
			}
			freeifaddrs(ifaddr);
			return buf;
		}
	}
	return NULL;
}



















