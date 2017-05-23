#include "DnsGenRandom.h"



DnsGenRandom::DnsGenRandom(DomainList * domainList)
    :
    domainList(domainList)
{
}


DnsGenRandom::~DnsGenRandom()
{
}

bool DnsGenRandom::GenerateQuery(uint8_t * buffer, uint32_t buffer_max, uint32_t * query_length)
{
    // Pick query ID in encrypted sequence

    // Pick random flags

    // Decide whether to do EDNS or not.

    // Decide to create non existing name or not.

    // Pick random name

    // Encode random name in query

    // Pick random RRTYPE, CLASS.

    return false;
}

/* 
 * Some flags and flag combinations make more sense than others.
 * bit 5 	AA 	Authoritative Answer 	[RFC1035]
 * bit 6 	TC 	Truncated Response 	[RFC1035]
 * bit 7 	RD 	Recursion Desired 	[RFC1035]
 * bit 8 	RA 	Recursion Available 	[RFC1035]
 * bit 9 		Reserved
 * bit 10 	AD 	Authentic Data 	[RFC4035][RFC6840][RFC Errata 4924]
 * bit 11 	CD 	Checking Disabled 	[RFC4035][RFC6840][RFC Errata 4927]
 * Valid combinations in queries:
 * RD or not;
 * AD bit or not; (Also see EDNS DO bit)
 * CD bit (checking disabled) or not, contradictory with DO bit.
 * Which leads to simple choice:
 * 1) If EDNS, DO or CD;
 * 2) If not EDNS, RD or not.
 */

uint8_t DnsGenRandom::RandomFlags()
{
    return uint8_t();
}

bool DnsGenRandom::RandomClassAndType(uint16_t * rrclass, uint16_t * rrtype)
{
    return false;
}
