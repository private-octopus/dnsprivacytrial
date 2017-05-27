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

bool DnsGenRandom::GenerateQuery(uint8_t * buffer, uint32_t buffer_max, 
    uint32_t * query_length)
{
    bool ret = (this->domainList != NULL &&  buffer_max >= (256 + 4 + 12));
    // Decide the scenario
    GenerateQueryEnum scenario = ERROR_NAME;
    uint32_t scenario_range = r.GetRandomUniform(TOTAL_WEIGHT);
    bool use_edns = true;
    bool rd_flag = true;
    bool cd_flag = false;
    bool do_flag = true;
    bool strip_www = false;
    uint16_t rrclass = 1;
    uint16_t rrtype = (uint16_t)/*DnsRtype::*/DnsRtype_ANY;
    uint16_t query_id = (uint16_t)r.GetRandomUniform(0x8000);
    uint32_t current_index = 0;

    if (ret)
    {
        if (scenario_range < DSNKEY_THRESHOLD)
        {
            // Cannot ask directy for DNSKEY!
            scenario = DNSKEY;
            rrtype = (uint16_t)/*DnsRtype::*/DnsRtype_DNSKEY;
            strip_www = true;
        }
        else if (scenario_range < TLSA_THRESHOLD)
        {
            scenario = TLSA;
            rrtype = (uint16_t)/*DnsRtype::*/DnsRtype_TLSA;
            strip_www = (r.GetRandomUniform(1000) > 500);
        }
        else if (scenario_range < SRV_THRESHOLD)
        {
            scenario = SRV;
            rrtype = (uint16_t)/*DnsRtype::*/DnsRtype_SRV;
            strip_www = true;
        }
        else
        {
            use_edns = (r.GetRandomUniform(1000) > 500);
            strip_www = (r.GetRandomUniform(1000) > 500);
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
            current_index = 12;
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
        current_index = 12;
    }

    if (ret)
    {
        /* Encode the name. TODO: perhaps find SOA for key */
        char const * dname = domainList->GetRandomDomain();

        if (scenario == ERROR_NAME && current_index < buffer_max)
        {
            /* insert a random name that has little chance of actually existing */
            buffer[current_index++] = 16;

            for (int i = 0; i < 16 && current_index < buffer_max; i++)
            {
                buffer[current_index++] = 'a' + r.GetRandomUniform(26);
            }
        }
        else if (scenario == SRV)
        {
            /* Pick a combination of service name and transport name,
             * and prepend it to the selected name */
            current_index = EncodeSRVPrefix(buffer, buffer_max, current_index);
        }

        if (dname != NULL)
        {
            current_index = EncodeDomainName(dname, strip_www, 
                buffer, buffer_max, current_index);
        }
        else
        {
            /* just the root name */
            if (current_index < buffer_max)
            {
                buffer[current_index++] = 0;
            }
        }
    }

    if (ret)
    {
        /* Encode the rrtype and rrclass */

        if (current_index + 4 > buffer_max)
        {
            current_index = buffer_max;
            ret = false;
        }
        else
        {
            buffer[current_index++] = (uint8_t)(rrtype >> 8);
            buffer[current_index++] = (uint8_t)(rrtype & 0xFF);
            buffer[current_index++] = (uint8_t)(rrclass >> 8);
            buffer[current_index++] = (uint8_t)(rrclass & 0xFF);
        }
    }

    if (use_edns)
    {
        /* if useful, encode the EDNS OPT record */
        current_index = EncodeEDNS(do_flag, 1400, buffer, buffer_max, current_index);
    }

    *query_length = current_index;
    return ret;
}

void DnsGenRandom::RandomClassAndType(uint16_t * rrclass, uint16_t * rrtype)
{
    uint32_t rrclass_random = r.GetRandomUniform(100);
    if (rrclass_random == 0)
    {
        *rrclass = 0;
        *rrtype = (uint16_t)/*DnsRtype::*/DnsRtype_SOA;
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

uint32_t DnsGenRandom::EncodeDomainName(char const * dname, bool strip_www,
    uint8_t * buffer, uint32_t buffer_max, uint32_t current_index)
{
    int name_index = 0;
    int last_dot_index = current_index++;

    if (strip_www)
    {
        int count_to_first_dot = 0;
        while (dname[count_to_first_dot] != 0 && dname[count_to_first_dot] != '.')
        {
            count_to_first_dot++;
        }

        if (dname[count_to_first_dot] != 0 &&
            count_to_first_dot >= 3 &&
            dname[0] == 'w' && dname[2] == 'w' && dname[2] == 'w')
        {
            name_index = count_to_first_dot + 1;
        }
    }


    while (current_index < buffer_max)
    {
        char x = dname[name_index];

        if (x == 0 || x == '.')
        {
            buffer[last_dot_index] = current_index - last_dot_index - 1;

            if (buffer[last_dot_index] == 0)
            {
                break;
            }
            else if (x == 0)
            {
                buffer[current_index++] = 0;
                break;
            }
            else
            {
                last_dot_index = current_index;
            }
        }
        else
        {
            buffer[current_index] = x;
        }

        current_index++;
        name_index++;
    }

    return current_index;
}

uint32_t DnsGenRandom::EncodeEDNS(bool do_flag, uint32_t packet_max, uint8_t * buffer, uint32_t buffer_max, uint32_t current_index)
{
    if (current_index + 11 <= buffer_max)
    {
        /* empty name */
        buffer[current_index++] = 0; 
        /* EDNS Opt Type */
        buffer[current_index++] = 0;
        buffer[current_index++] = /*DnsRtype::*/DnsRtype_OPT; 
        /* class = packet length */
        buffer[current_index++] = (uint8_t)(packet_max >> 8);
        buffer[current_index++] = (uint8_t)(packet_max & 0xFF); 
        /* TTL = extended RCODE and FLAGS */
        buffer[current_index++] = 0; /* Extended Rcode */
        buffer[current_index++] = 0; /* Version 0, per RFC 6891 */
        buffer[current_index++] = (do_flag) ? 0x80 : 0;
        buffer[current_index++] = 0;
        /* No OPT data yet, hence payload length = 0 */
        buffer[current_index++] = 0;
        buffer[current_index++] = 0;
    }

    return current_index;
}

static char const * SrvPrefixes[] = {
    "_sip._udp",
    "_sip._tcp",
    "_sips._tcp",
    "_iax._udp",
    "_h323cs._tcp",
    "_h323ls._udp",
    "_h323rs._udp",
    "_stun._udp",
    "_turn._udp",
    "_http._tcp",
    "_autodiscover._tcp",
    "_ldap._tcp",
    "_gc._tcp",
    "_kerberos._udp",
    "_kerberos._tcp",
    "_kpasswd._tcp",
    "_kpasswd._udp",
    "_ftp._tcp",
    "_smtp._tcp",
    "_imap._tcp",
    "_imaps._tcp",
    "_pop3._tcp",
    "_pop3s._tcp"
};

static const uint32_t nbSrvPrefixes = sizeof(SrvPrefixes) / sizeof(char const *);

uint32_t DnsGenRandom::EncodeSRVPrefix(uint8_t * buffer, uint32_t buffer_max, uint32_t current_index)
{
    /* Add a domain name */
    current_index = EncodeDomainName(
        SrvPrefixes[r.GetRandomUniform(nbSrvPrefixes)], false,
        buffer, buffer_max, current_index);
    /* And remove the last part, which contains the root name */
    if (current_index < buffer_max)
    {
        current_index--;
    }
    return current_index;
}
