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
};

