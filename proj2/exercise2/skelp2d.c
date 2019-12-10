// Compile with "gcc encap.c -o encap" with minGW

#define _LARGEFILE64_SOURCE    1

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h> 
#include <unistd.h>
#include <sys/types.h>
#include "encap.h"



u_short ush_endian_swp(u_short p);
unsigned int uint_endian_swp(unsigned int p);
int isgetTCPIP(BYTE *pcktbuf, u_int *size_ip, u_int *size_tcp,FILE *);

struct sniff_ethernet *ethernet;  /* The ethernet header */
struct sniff_tcp *tcp; /* The TCP header */
struct sniff_ip *ip;  /* The IP header */
char *payload; /* Packet payload */



main(int argc,char **argv)
{
	FILE *InRaw,*fp, *payloadData, *transferred;


	struct stat filedat;
	off_t InLen, currpos;
	
	//off64_t InLen, currpos;
	struct pcap_file_header pcapfilehdr;
	struct pcap_pkthdr pckthdr;
	BYTE pcktbuf[65535];
	u_int size_ip;
	u_int size_tcp;
	unsigned int pcktcnt=0;
	


	if(argc<2) 
		{
		printf("ERROR: Too few input arguments\n");
		printf("Usage: encap input.pcap \n");
		return 0;
		}
	if(stat(*(argv+1),&filedat)==-1)
		{
		printf("ERROR: Can't get length of input file\n");
		return 0;
		}
	InLen=filedat.st_size;



	if((fp=fopen("outdata.txt", "w")) == NULL) {
		printf("Cannot open outdata.txt file.\n");
		return(0);
	  }

	  if((transferred=fopen("transfer.txt", "w")) == NULL) {
		printf("Cannot open outdata.txt file.\n");
		return(0);
	  }


	  if((payloadData=fopen("payloadData.txt", "w")) == NULL) {
		printf("Cannot open payloadData.txt file.\n");
		return(0);
	  }

	//InRaw=fopen64(*(argv+1),"rb");
	InRaw=fopen(*(argv+1),"rb");

	if(InRaw==NULL)
		{
		printf("ERROR: Can't open file\n");
		return(0);
		}


	printf("Done \n\n",InLen);
	if (fread((char *) &pcapfilehdr, sizeof(pcapfilehdr), 1, InRaw) != 1) {
		printf("0) Fread for pcap file header failed\n");
		return(-1);
	}


//	currpos = ftello64(InRaw);
	currpos = ftello(InRaw);

	int firstGot = 0;

int totalSize = 0;

	while (currpos < InLen){



		pcktcnt++;
		//currpos = ftello64(InRaw);

		currpos = ftello(InRaw);
		if (fread((char *) &pckthdr, sizeof(pckthdr), 1, InRaw) != 1) {
			break;
		}

		if (fread((char *) &pcktbuf, pckthdr.caplen, 1, InRaw) != 1) {
				break;
		}

		/* Find stream in file, count packets and get size (in bytes) */
		if( isgetTCPIP(pcktbuf, &size_ip, &size_tcp,fp)){
			/* Simple example code */
			//fprintf(fp, "packet: %d, type: %u \n",pcktcnt,ethernet->ether_type);



			unsigned int seqNumRet = 0;
			unsigned int ackNumRet = 0;
			
			seqNumRet = uint_endian_swp(tcp->th_seq);
			//seqNumRet = (tcp->th_seq);
			

			ackNumRet = uint_endian_swp(tcp->th_ack);
			//ackNumRet = (tcp->th_ack);

			char srcString[20];
			char dstString[20];

			BYTE addressSrc[4];
			memcpy(&addressSrc[0], &(ip->ip_src.S_un.S_un_b.s_b1), sizeof(BYTE));
			memcpy(&addressSrc[1], &(ip->ip_src.S_un.S_un_b.s_b2), sizeof(BYTE));
			memcpy(&addressSrc[2], &(ip->ip_src.S_un.S_un_b.s_b3), sizeof(BYTE));
			memcpy(&addressSrc[3], &(ip->ip_src.S_un.S_un_b.s_b4), sizeof(BYTE));

			BYTE addressDst[4];
			memcpy(&addressDst[0], &(ip->ip_dst.S_un.S_un_b.s_b1), sizeof(BYTE));
			memcpy(&addressDst[1], &(ip->ip_dst.S_un.S_un_b.s_b2), sizeof(BYTE));
			memcpy(&addressDst[2], &(ip->ip_dst.S_un.S_un_b.s_b3), sizeof(BYTE));
			memcpy(&addressDst[3], &(ip->ip_dst.S_un.S_un_b.s_b4), sizeof(BYTE));


			fprintf(fp, "packet: %d, Source IPv4: ",pcktcnt); 

			fprintf(fp, "%u.%u.%u.%u ", addressSrc[0], addressSrc[1], addressSrc[2], addressSrc[3]);

			sprintf(srcString, "%u.%u.%u.%u", addressSrc[0], addressSrc[1], addressSrc[2], addressSrc[3]);

			fprintf(fp,"and port: %u, Dest IPv4: ", ush_endian_swp(tcp->th_sport));

			fprintf(fp, "%u.%u.%u.%u ", addressDst[0], addressDst[1], addressDst[2], addressDst[3]);

			sprintf(dstString, "%u.%u.%u.%u", addressDst[0], addressDst[1], addressDst[2], addressDst[3]);


			fprintf(fp,"and Port: %u, Seq Num: %u, Ack Num: %u  \n", ush_endian_swp(tcp->th_dport), seqNumRet, ackNumRet);


			unsigned short payloadSize = ush_endian_swp(ip->ip_len);

			payloadSize -= size_ip;

			payloadSize -= size_tcp;

totalSize += payloadSize;

			if(payloadSize !=0) //strcmp("129.21.27.161", srcString)==0 && strcmp("129.21.27.12", dstString)==0)
			{


	//				fprintf(payloadData, "%s\n", payload);	





			
				
					firstGot = seqNumRet;
					fprintf(payloadData, "packet: %d, Seq Num: %u, PLoad Size: %hu\n", 
						pcktcnt, seqNumRet, payloadSize);


					for(int iter =0; iter<payloadSize; iter++)
					{
					
						fprintf(transferred, "%c", *(payload+iter));
					}
					//first

				



			}
			





		}  // isgetTCPIP

	} //while currpos < InLen

	fprintf(payloadData, "Total file transferred: %d\n", totalSize);

	fclose(InRaw);
	fclose(fp);
	fclose(payloadData);
	fclose(transferred);
	return(0);

}

u_short ush_endian_swp(u_short p)
{
    	u_short res;
    	char *h = (char *)(&p);
    	char *hr = (char *)(&res);



	hr[0]=h[1];
	hr[1]=h[0];

	return res;
}

unsigned int uint_endian_swp(unsigned int p)
{
    	unsigned int res;
    	char *h = (char *)(&p);
    	char *hr = (char *)(&res);

	hr[0]=h[3];
	hr[1]=h[2];
	hr[2]=h[1];	
	hr[3]=h[0];

	return res;
}



int isgetTCPIP(BYTE *pcktbuf, u_int *size_ip, u_int *size_tcp,FILE *fp)
{
		ethernet = (struct sniff_ethernet*)(pcktbuf);

		if(ush_endian_swp(ethernet->ether_type) == IPTYPEETHER){ // IP only past here

			ip = (struct sniff_ip*)(pcktbuf + SIZE_ETHERNET);
			
			*size_ip = IP_HL(ip)*4;
			if (*size_ip < 20) {
				printf("   * Invalid IP header length: %u bytes\n", *size_ip);
				return 0;
			}

			if(ip->ip_p == TCPPRTCL){ // TCP only past here
				tcp = (struct sniff_tcp*)(pcktbuf + SIZE_ETHERNET + *size_ip);
				*size_tcp = TH_OFF(tcp)*4;

				if (*size_tcp < 20) {
					printf("   * Invalid TCP header length: %u bytes\n", *size_tcp);
					return 0;
				}
				payload = (u_char *)(pcktbuf + SIZE_ETHERNET + *size_ip + *size_tcp);

				printf("%x\n", payload);

				return 1;
			} // only TCP
		} // only IP
		return 0;
}



