#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

struct ethheader {
	u_char ether_dhost[6];
	u_char ether_shost[6];
	u_short ether_type;
};

struct ipheader {
	unsigned char iph_ihl:4,
		      iph_ver:4;
	unsigned char iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_flag:3,
		 	iph_offset:13;
	unsigned char iph_ttl;
	unsigned char iph_protocol;
	unsigned short int iph_chksum;
	struct in_addr iph_sourceip;
	struct in_addr iph_destip;
};

struct tcpheader {
	u_short tcp_sport;
	u_short tcp_dport;
	u_int tcp_seq;
	u_int tcp_ack;
	u_char tcp_offx2;
	u_char tcp_flags;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
		const u_char *packet)
{
	struct ethheader *eth = (struct ethheader *)packet;
	int clientSocket = socket(AF_INET, SOCK_STREAM,0);
	char buffer[1024];
		
	if(ntohs(eth->ether_type) == 0x0800){
		struct ipheader * ip = (struct ipheader *)
					(packet + sizeof(struct ethheader));
		struct tcpheader * tcp = (struct tcpheader *)
					(packet + sizeof(struct ethheader));
		switch(ip->iph_protocol){
                        case IPPROTO_TCP:
                                printf("\n        Protocol: TCP\n\n");
                                break;
                        default:
                                printf("\n        Protocol: others\n\n");
                                break;
        }

		printf("	From: %s\n", inet_ntoa(ip->iph_sourceip));
		printf("	To: %s\n", inet_ntoa(ip->iph_destip));	
		printf("	From (MAC) : ");
		for(int i=0;i<6;i++){
			printf("%02x",eth->ether_shost[i]);
			if(i<5) printf(":");}
	       	printf("\n	To (MAC) : ");
		for(int i=0;i<6;i++){
			printf("%02x",eth->ether_dhost[i]);
			if(i<5) printf(":");}
		printf("\n	Src Port : %d\n", tcp->tcp_sport);
		printf("	Dst Port : %d\n", tcp->tcp_dport);

		int recv_len = recv(clientSocket,buffer,sizeof(buffer),0);
		printf("======================\n");
		printf("Message : %s\n", buffer);
		printf("======================\n");

	}

	close(clientSocket);
}

int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "tcp";
	bpf_u_int32 net;

	handle = pcap_open_live("enp0s3",BUFSIZ,1,1000,errbuf);

	pcap_compile(handle,&fp,filter_exp,0,net);
	if(pcap_setfilter(handle,&fp)!=0){
		pcap_perror(handle,"Error:");
		exit(EXIT_FAILURE);
	}

	pcap_loop(handle,-1,got_packet,NULL);
	pcap_close(handle);
	return 0;
}
