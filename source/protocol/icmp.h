#pragma once 

#include <stdint.h>
#include "ip.h"

struct icmp_header {
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_checksum;
    uint16_t icmp_identifier;
    uint16_t icmp_seqnum;
};