#pragma once

#include <stdint.h>
#include "DomainList.h"

/*
 * Generation of random DNS queries
 */

class DnsGenRandom
{
public:
    DnsGenRandom(DomainList * domainList);
    ~DnsGenRandom();

    bool GenerateQuery(uint8_t * buffer, uint32_t buffer_max, uint32_t * query_length);

private:
    RandGen r;
    DomainList * domainList;
    uint16_t count_in_epoch;
    uint16_t epoch_bit;

    void RandomClassAndType(uint16_t * rrclass, uint16_t * rrtype);

    uint32_t EncodeDomainName(char const * dname, bool strip_www,
        uint8_t * buffer, uint32_t buffer_max, uint32_t current_index);

    uint32_t EncodeEDNS(bool do_flag, uint32_t packet_max,
        uint8_t * buffer, uint32_t buffer_max, uint32_t current_index);

    uint32_t EncodeSRVPrefix(
        uint8_t * buffer, uint32_t buffer_max, uint32_t current_index);
};

