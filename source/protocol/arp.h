#pragma once 

#include <stdint.h>
#include "ip.h"
#include "ethernet.h"

struct arp_header {
	uint16_t ar_hrd;		
	uint16_t ar_pro;		
	uint8_t ar_hln;		
	uint8_t ar_pln;		
	uint16_t ar_op;		

	mac_addr ar_sha;	
	ip_addr ar_sip;		
	mac_addr ar_tha;	
	ip_addr ar_tip;		
};