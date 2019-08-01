#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include "protocol/all.h"

void usage()
{
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

bool equalIPAddress(ip_addr x, ip_addr y){
	return memcmp(&x, &y,sizeof(ip_addr)) == 0;
}

bool equalMacAddress(mac_addr x, mac_addr y){
	if(x.nic[0] == y.nic[0] && x.nic[1] == y.nic[1] && x.nic[2] == y.nic[2] && x.oui[0] == y.oui[0] && x.oui[1] == y.oui[1] && x.oui[2] == y.oui[2]){
		return true;
	}
	else 	
		return false;
}

void printIPAddress(ip_addr ipAddr)
{
	printf("%d.%d.%d.%d\n",ipAddr.a, ipAddr.b, ipAddr.c, ipAddr.d);
}

void printMACAddress(mac_addr mac)
{
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac.oui[0], mac.oui[1], mac.oui[2], mac.nic[0], mac.nic[1], mac.nic[2]);
}

void printpacket(const unsigned char *p, uint32_t size)
{
	int len = 0;
	int i = 0;
	printf("00%d0 : ", i++);
	while (len < size)
	{
		printf("%02X ", *(p++));
		if (((len + 1) % 8) == 0){
			printf(" ");
		}
		if (!(++len % 16) && size / 16 != 0){
			if(i / 10 == 0)
				printf("\n00%d0 : ",i++);
			else if(i / 100 == 0)
				printf("\n0%d0 : ",i++);
			else if(i / 1000 == 0)
				printf("\n%d0 : ",i++);

		}
	}
	if (size % 16)
		printf("\n");
}

void printpacketask(const unsigned char *p, uint32_t size)
{
	int len = 0;
	int i = 0;
	printf("00%d0 : ", i++);
	while (len < size)
	{
		printf("%02X ", *(p++));
		if (((len + 1) % 8) == 0){
			printf(" ");
		}
		if (!(++len % 16) && size / 16 != 0){
			if(i / 10 == 0){
				p -= 16;
				len -= 16;
				while (len < size)
				{
					printf("%c", *p >= 32 && *p <= 126 ? *p : '.' );
					p++;
					if (!(++len % 16))
							break;
				}
				// if (size % 16)
				// printf("\n");
				printf("\n00%d0 : ",i++);
			}
			else if(i / 100 == 0){
				p -= 16;
				len -= 16;
				while (len < size)
				{
					printf("%c", *p >= 32 && *p <= 126 ? *p : '.' );
					if (!(++len % 16))
							break;
				}
				// if (size % 16)
				// printf("\n");
				printf("\n0%d0 : ",i++);
			}
			else if(i / 1000 == 0){
				p -= 16;
				len -= 16;
				while (len < size)
				{
					printf("%c", *p >= 32 && *p <= 126 ? *p : '.' );
					if (!(++len % 16))
							break;
				}
				// if (size % 16)
				// printf("\n");
				printf("\n%d0 : ",i++);
			}
		}
	}	
			if(len % 16 < 8){
				printf(" ");
				for(int j = 0;j < 15 - len % 16;j++){
					printf("   ");
				}
				printf("    ");
			}

			else if(len % 16 >= 8){
				for(int j = 0;j < 15 - len % 16;j++){
					printf("   ");
				}
				printf("    ");
			}

			p -= (len)% 16;
			int a = (len) % 16;
			len -= a;
			for(int  j = 0; j < a;j++)
				{
					printf("%c", *p >= 32 && *p <= 126 ? *p : '.' );
					p++;
				}
		
	if (size % 16)
		printf("\n");
}	

// void cheakhttp(const u_char *data)
// {
//     int i,j;
//     char cheak[7];

//     for(i = 0;i < 7; i++)
//     {
//         cheak[i] = data[i];
//     }

//     for(i = 0;i < 9;i++){
//         for(j = 0;j < strlen((char*)HTTP_METHOD[i]);j++){
//             if(strncmp(cheak,(char*)data,strlen((char*)HTTP_METHOD[i])) == 0)
//             {
//                 printf("http_method: %s\n",data);
//             } 

//         }
//     }
// }


// }
// void printpacketask(const unsigned char *p, uint32_t size)
// {
// 	int len = 0;
// 	while (len < size)
// 	{
// 		printf("%c", p[len] >= 32 && p[len] <= 126 ? p[len] : '.' );
// 		if (!(++len % 16))
// 			printf("\n");
// 	}
// 	if (size % 16)
// 		printf("\n");
// }

