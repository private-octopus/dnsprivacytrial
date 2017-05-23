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

    uint8_t RandomFlags();
    bool RandomClassAndType(uint16_t * rrclass, uint16_t * rrtype);
};

