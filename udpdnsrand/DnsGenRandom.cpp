#include "../dnsPrivacyTrial/DnsTypes.h"
#include "DnsGenRandom.h"



DnsGenRandom::DnsGenRandom(DomainList * domainList)
    :
    domainList(domainList),
    count_in_epoch(0),
    epoch_bit(0)
{
}


DnsGenRandom::~DnsGenRandom()
{
}

/*
 * We want to get some random records. The goal of the test include:
 * - Collecting some DNSKEY and TLSA records for further analysis
 * - Checking the presence of a variety of record types.
 * - in the case of SRV records, check the presence of a variety of _service._protocol combinations.
 * - Elicit responses with a variety of flags.
 * - Elicit some name or record errors.
 * The first action is to pick one of the previous options. This is achieved by picking
 * a uniform random number in the 0..1000 range, and using it to draw a scenario. In the
 * case of the srv record, a secondary scenario will be used to pick the specific service.
 *
 * The queried name is normally picked at random from the catalog. There may be a need at some point
 * to constrain the domain name, e.g. to reduce it to a second level domain, or to the beginning of
 * a zone. That will be tested later.
 *
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
 * 1) if DNSSEC, require EDNS, DO and CD;
 * 2) If EDNS, DO or CD;
 * 3) If not EDNS, RD or not.
 */

enum GenerateQueryEnum {
    DNSKEY,
    TLSA,
    SRV,
    RANDOM_RECORD_AND_FLAGS,
    ERROR_NAME
};

static const uint32_t DSNKEY_WEIGHT = 200;
static const uint32_t DSNKEY_THRESHOLD = DSNKEY_WEIGHT;
static const uint32_t TLSA_WEIGHT = 200;
static const uint32_t TLSA_THRESHOLD = DSNKEY_THRESHOLD + TLSA_WEIGHT;
static const uint32_t SRV_WEIGHT = 200;
static const uint32_t SRV_THRESHOLD = TLSA_THRESHOLD + SRV_WEIGHT;
static const uint32_t RANDOM_RECORD_WEIGHT = 200;
static const uint32_t RANDOM_RECORD_THRESHOLD = SRV_THRESHOLD + RANDOM_RECORD_WEIGHT;
static const uint32_t ERROR_NAME_WEIGHT = 200;
static const uint32_t TOTAL_WEIGHT = RANDOM_RECORD_THRESHOLD + ERROR_NAME_WEIGHT;

bool DnsGenRandom::GenerateQuery(uint8_t * buffer, uint32_t buffer_max, uint32_t * query_length)
{
    bool ret = buffer_max >= (256 + 4 + 12);

    // Decide the scenario
    GenerateQueryEnum scenario = ERROR_NAME;
    uint32_t scenario_range = r.GetRandomUniform(TOTAL_WEIGHT);
    bool use_edns = true;
    bool rd_flag = true;
    bool cd_flag = false;
    bool do_flag = true;
    uint16_t rrclass = 1;
    uint16_t rrtype = (uint16_t)DnsRtype::DnsRtype_A;
    uint16_t query_id = (uint16_t)r.GetRandomUniform(0x8000);

    if (ret)
    {
        if (scenario_range < DSNKEY_THRESHOLD)
        {
            scenario = DNSKEY;
            rrtype = (uint16_t)DnsRtype::DnsRtype_DNSKEY;
        }
        else if (scenario_range < TLSA_THRESHOLD)
        {
            scenario = TLSA;
            rrtype = (uint16_t)DnsRtype::DnsRtype_DNSKEY;
        }
        else if (scenario_range < SRV_THRESHOLD)
        {
            scenario = SRV;
            rrtype = (uint16_t)DnsRtype::DnsRtype_SRV;
            /* TODO: extra name components for SRV */
        }
        else
        {
            use_edns = (r.GetRandomUniform(1000) > 500);
            rd_flag = (r.GetRandomUniform(1000) > 500);
            do_flag = use_edns && (r.GetRandomUniform(1000) > 500);
            cd_flag = use_edns && !do_flag && (r.GetRandomUniform(1000) > 500);

            if (scenario_range < RANDOM_RECORD_THRESHOLD)
            {
                scenario = RANDOM_RECORD_AND_FLAGS;
                RandomClassAndType(&rrclass, &rrtype);
            }
            else
            {
                scenario = ERROR_NAME;
            }
        }
        // Pick query ID in epoch
        count_in_epoch++;
        if (count_in_epoch > 0x8000)
        {
            epoch_bit ^= 0x8000;
        }
        query_id |= epoch_bit;

        // Create the header
        buffer[0] = (uint8_t) (query_id >> 8);
        buffer[1] = (uint8_t)(query_id & 0xFF);
        buffer[2] = (rd_flag) ? 1 : 0;
        buffer[3] = (cd_flag) ? 16 : 0;
        buffer[4] = 0;
        buffer[5] = 1; /* QDCOUNT */
        buffer[6] = 0;
        buffer[7] = 0; /* ANCOUNT */
        buffer[8] = 0;
        buffer[9] = 0; /* NSCOUNT */
        buffer[10] = 0;
        buffer[11] = (use_edns) ? 1 : 0; /* ARCOUNT */

        /* Encode the name. TODO: error names, srv names, perhaps SOA for key */

        /* Encode the rrtype and rrclass */

        /* if useful, encode the EDNS OPT record */
    }

    
    // Encode random name in query

    // Pick random RRTYPE, CLASS.

    return false;
}

void DnsGenRandom::RandomClassAndType(uint16_t * rrclass, uint16_t * rrtype)
{
    uint32_t rrclass_random = r.GetRandomUniform(100);
    if (rrclass_random == 0)
    {
        *rrclass = 0;
        *rrtype = (uint16_t)DnsRtype::DnsRtype_SOA;
    }
    else if (rrclass_random == 1)
    {
        *rrclass = (uint16_t) r.GetRandomUniform(100);
        *rrtype = (uint16_t) r.GetRandomUniform(65536);
    }
    else
    {
        uint32_t rrtype_random = r.GetRandomUniform(300);
        *rrclass = 1;

        if (rrtype_random < 258)
        {
            *rrtype = rrtype_random + 1;
        }
        else if (rrtype_random < 260)
        {
            *rrtype = rrtype_random - 258 + 32768;
        }
        else
        {
            *rrtype = (uint16_t)r.GetRandomUniform(65536);
        }
    }
}
