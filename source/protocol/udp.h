#pragma once 

#include <stdint.h>

#define ARPHRD_ENTER 1

#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

struct udp_header
{
	uint16_t source;
	uint16_t dest;
	uint16_t _len;
	uint16_t check;
};