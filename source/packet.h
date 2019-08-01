#pragma once
#include <stdio.h>
#include <stdint.h>
#include "protocol/all.h"

void usage();
bool equalIPAddress(ip_addr x, ip_addr y);
bool equalMacAddress(mac_addr x, mac_addr y);
void printIPAddress(ip_addr ipAddr);
void printMACAddress(mac_addr mac);
void printpacket(const unsigned char *p, uint32_t size);
void printpacketask(const unsigned char *p, uint32_t size);
void cheakhttp(const unsigned char *data);
