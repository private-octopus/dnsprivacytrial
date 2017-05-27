#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../dnsPrivacyTrial/DnsTypes.h"
#include "DnsStats.h"

DnsStatHash::DnsStatHash()
    :
    tableSize(0),
    tableCount(0),
    hashTable(NULL)
{
}


DnsStatHash::~DnsStatHash()
{
    Clear();
}

void DnsStatHash::Clear()
{
    if (hashTable != NULL)
    {
        for (uint32_t i = 0; i < tableSize; i++)
        {
            if (hashTable[i] != NULL)
            {
                delete hashTable[i];
                hashTable[i] = NULL;
            }
        }

        delete[] hashTable;
        hashTable = NULL;
    }

    tableCount = 0;
    tableSize = 0;
}

bool DnsStatHash::Resize(unsigned newSize)
{
    bool ret = false;
    dns_registry_entry_t ** oldTable = hashTable;
    unsigned int oldSize = tableSize;

    if (oldSize >= newSize)
    {
        ret = true;
    }
    else
    {
        dns_registry_entry_t ** newTable = new dns_registry_entry_t*[newSize];

        if (newTable != NULL)
        {
            hashTable = newTable;
            tableSize = newSize;
            memset(hashTable, 0, sizeof(dns_registry_entry_t *)*tableSize);
            ret = true;
            tableCount = 0;

            if (oldTable != NULL)
            {
                for (unsigned int i = 0; ret && i < oldSize; i++)
                {
                    if (oldTable[i] != NULL)
                    {
                        ret = DoInsert(oldTable[i], false);
                    }
                }

                if (!ret)
                {
                    hashTable = oldTable;
                    tableSize = oldSize;
                    delete[] newTable;
                }
                else
                {
                    delete[] oldTable;
                }
            }
        }
    }

    return ret;
}

bool DnsStatHash::InsertOrAdd(dns_registry_entry_t* key, bool need_alloc)
{
    bool ret = true;
    unsigned int newCount = tableCount + 1;

    if (key == 0)
    {
        ret = false;
    }
    else if (tableSize < 2 * newCount)
    {
        unsigned int newSize = tableSize;

        if (tableSize == 0)
        {
            newSize = 128;
        }

        while (newSize < 4 * newCount)
        {
            newSize *= 2;
        }

        ret = Resize(newSize);
    }

    if (ret)
    {
        key->hash = ComputeHash(key);
        ret = DoInsert(key, need_alloc);
    }

    return ret;
}

uint32_t DnsStatHash::GetCount() {
    return tableCount;
}

uint32_t DnsStatHash::GetSize() {
    return tableSize;
}

dns_registry_entry_t * DnsStatHash::GetEntry(uint32_t indx)
{
    return (indx < tableSize) ? hashTable[indx] : NULL;
}

bool DnsStatHash::DoInsert(dns_registry_entry_t* key, bool need_alloc)
{
    bool ret = false;
    unsigned int hash_index = key->hash%tableSize;

    for (unsigned int i = 0; i < tableSize; i++)
    {
        if (hashTable[hash_index] == NULL)
        {
            if (need_alloc)
            {
                hashTable[hash_index] = new dns_registry_entry_t;
                if (hashTable[hash_index] != NULL)
                {
                    memcpy(hashTable[hash_index], key, sizeof(dns_registry_entry_t));

                    tableCount++;
                    ret = true;
                }
                else
                {
                    ret = false;
                }
            }
            else
            {
                hashTable[hash_index] = key;
                tableCount++;
                ret = true;
            }
            break;
        }
        else if (IsSameKey(hashTable[hash_index], key))
        {
            /* found it. Just increment the counter */
            hashTable[hash_index]->count++;
            ret = false;
            break;
        }
        else
        {
            hash_index++;

            if (hash_index >= tableSize)
            {
                hash_index = 0;
            }
        }
    }

    return ret;
}

uint32_t DnsStatHash::ComputeHash(dns_registry_entry_t * key)
{
    uint64_t hash64 = 0;

    hash64 = key->registry_id;
    hash64 ^= (hash64 << 23) ^ (hash64 >> 17);
    hash64 ^= key->key_type;
    hash64 ^= (hash64 << 23) ^ (hash64 >> 17);
    hash64 ^= key->key_length;
    hash64 ^= (hash64 << 23) ^ (hash64 >> 17);
    for (uint32_t i = 0; i < key->key_length; i++)
    {
        hash64 ^= key->key_value[i];
        hash64 ^= (hash64 << 23) ^ (hash64 >> 17);
    }

    return (uint32_t)(hash64 ^ (hash64 >> 32));
}

bool DnsStatHash::IsSameKey(dns_registry_entry_t * key1, dns_registry_entry_t * key2)
{
    bool ret = key1->hash == key2->hash &&
        key1->registry_id == key2->registry_id &&
        key1->key_type == key2->key_type &&
        key1->key_length == key2->key_length &&
        memcmp(key1->key_value, key2->key_value, key1->key_length) == 0;

    return ret;
}


DnsStats::DnsStats()
{
}


DnsStats::~DnsStats()
{
}

static char const * RegistryNameById[] = {
    "0",
    "CLASS",
    "RR Type",
    "OpCode",
    "RCODE",
    "AFSDB RRSubtype",
    "DHCID RRIdType",
    "Label Type",
    "EDNS OPT CODE",
    "Header Flags",
    "EDNS Header_Flags",
    "EDNS Version number",
    "CSYNC Flags",
    "DNSSEC Algorithm Numbers",
    "DNSSEC KEY Prime Lengths",
    "Q-CLASS",
    "Q-RR Type",
    "DNSSEC Well Known Primes"
};

static uint32_t RegistryNameByIdNb = sizeof(RegistryNameById) / sizeof(char const*);

int DnsStats::SubmitQuery(uint8_t * packet, uint32_t length, uint32_t start)
{
    int rrclass = 0;
    int rrtype = 0;

    start = SubmitName(packet, length, start);

    if (start + 4 <= length)
    {
        rrtype = (packet[start] << 8) | packet[start + 1];
        rrclass = (packet[start + 2] << 8) | packet[start + 3];
        start += 4;
        SubmitRegistryNumber(REGISTRY_DNS_Q_CLASSES, rrclass);
        SubmitRegistryNumber(REGISTRY_DNS_Q_RRType, rrtype);
    }
    else
    {
        start = length;
    }

    return start;
}

int DnsStats::SubmitRecord(uint8_t * packet, uint32_t length, uint32_t start, uint32_t * e_rcode)
{
    int rrtype = 0;
    int rrclass = 0;
    unsigned int ttl = 0;
    int ldata = 0;

    /* TODO: if TXT record, analyze labels for underscores */

    start = SubmitName(packet, length, start);

    if ((start + 10) > length)
    {
        start = length;
    }
    else
    {
        rrtype = (packet[start] << 8) | packet[start + 1];
        rrclass = (packet[start + 2] << 8) | packet[start + 3];
        ttl = (packet[start + 4] << 24) | (packet[start + 5] << 16)
            | (packet[start + 6] << 8) | packet[start + 7];
        ldata = (packet[start + 8] << 8) | packet[start + 9];

        if (start + ldata + 10 > length)
        {
            start = length;
        }
        else
        {
            if (ldata > 0 || rrtype == /*DnsRtype::*/DnsRtype_OPT)
            {
                /* only record rrtypes and rrclass if valid response */
                if (rrtype != /*DnsRtype::*/DnsRtype_OPT)
                {
                    SubmitRegistryNumber(REGISTRY_DNS_CLASSES, rrclass);
                }
                SubmitRegistryNumber(REGISTRY_DNS_RRType, rrtype);

                /* Further parsing for OPT, DNSKEY, RRSIG, DS,
                 * and maybe also AFSDB, NSEC3, DHCID, RSYNC types */
                switch (rrtype)
                {
                case (int)/*DnsRtype::*/DnsRtype_OPT:
                    SubmitOPTRecord(ttl, &packet[start + 10], ldata, e_rcode);
                    break;
                case (int)/*DnsRtype::*/DnsRtype_DNSKEY:
                    SubmitKeyRecord(&packet[start + 10], ldata);
                    break;
                case (int)/*DnsRtype::*/DnsRtype_RRSIG:
                    SubmitRRSIGRecord(&packet[start + 10], ldata);
                    break;
                case (int)/*DnsRtype::*/DnsRtype_DS:
                    SubmitDSRecord(&packet[start + 10], ldata);
                    break;
                default:
                    break;
                }
            }

            start += ldata + 10;
        }
    }

    return start;
}

int DnsStats::SubmitName(uint8_t * packet, uint32_t length, uint32_t start)
{
    uint32_t l = 0;
    uint32_t offset = 0;

    while (start < length)
    {
        l = packet[start];

        if (l == 0)
        {
            /* end of parsing*/
            start++;
            break;
        }
        else if ((l & 0xC0) == 0xC0)
        {
            /* Name compression */
            if ((start + 2) > length)
            {
                start = length;
                break;
            }
            else
            {
                start += 2;
                break;
            }
        }
        else if (l > 0x3F)
        {
            /* found an extension. Don't know how to parse it! */
            SubmitRegistryNumber(REGISTRY_DNS_LabelType, l);
            start = length;
            break;
        }
        else
        {
            /* regular name part. To do: tracking of underscore labels. */
            if (start + l + 1 > length)
            {
                start = length;
                break;
            }
            else
            {
                start += l + 1;
            }
        }
    }

    return start;
}

void DnsStats::SubmitOPTRecord(uint32_t flags, uint8_t * content, uint32_t length, uint32_t * e_rcode)
{
    uint32_t current_index = 0;

    /* Process the flags and rcodes */
    if (e_rcode != NULL)
    {
        *e_rcode = (flags >> 24) & 0xFF;
    }

    for (int i = 0; i < 16; i++)
    {
        if ((flags & (1 << i)) != 0)
        {
            SubmitRegistryNumber(REGISTRY_EDNS_Header_Flags, i);
        }
    }

    SubmitRegistryNumber(REGISTRY_EDNS_Version_number, (flags >> 16) & 0xFF);

    /* Find the options in the payload */
    while (current_index + 4 <= length)
    {
        uint32_t o_code = (content[current_index] << 8) | content[current_index + 1];
        uint32_t o_length = (content[current_index+2] << 8) | content[current_index + 3];
        current_index += 4 + o_length;

        SubmitRegistryNumber(REGISTRY_EDNS_OPT_CODE, o_code);
    }
}

void DnsStats::SubmitKeyRecord(uint8_t * content, uint32_t length)
{
    if (length > 8)
    {
        uint32_t algorithm = content[3];
        SubmitRegistryNumber(REGISTRY_DNSSEC_Algorithm_Numbers, algorithm);

        if (algorithm == 2)
        {
            uint32_t prime_length = (content[4] << 8) | content[5];
            if (prime_length < 16)
            {
                SubmitRegistryNumber(REGISTRY_DNSSEC_KEY_Prime_Lengths, prime_length);

                if (prime_length == 1 || prime_length == 2)
                {
                    uint32_t well_known_prime = (content[6] << 8) | content[7];
                    SubmitRegistryNumber(REGISTRY_DNSSEC_KEY_Well_Known_Primes, well_known_prime);
                }
            }
        }
    }
}

void DnsStats::SubmitRRSIGRecord(uint8_t * content, uint32_t length)
{
    if (length > 18)
    {
        uint32_t algorithm = content[2];
        SubmitRegistryNumber(REGISTRY_DNSSEC_Algorithm_Numbers, algorithm);
    }
}

void DnsStats::SubmitDSRecord(uint8_t * content, uint32_t length)
{
    if (length > 4)
    {
        uint32_t algorithm = content[2];
        SubmitRegistryNumber(REGISTRY_DNSSEC_Algorithm_Numbers, algorithm);
    }
}

void DnsStats::SubmitRegistryNumber(uint32_t registry_id, uint32_t number)
{
    dns_registry_entry_t key;

    key.count = 1;
    key.registry_id = registry_id;
    key.key_length = sizeof(uint32_t);
    key.key_type = 0; /* number */
    key.key_number = number;

    (void)hashTable.InsertOrAdd(&key);
}

void DnsStats::SubmitRegistryString(uint32_t registry_id, uint32_t length, uint8_t * value)
{
    dns_registry_entry_t key;

    if (length < 64)
    {
        key.count = 1;
        key.registry_id = registry_id;
        key.key_length = length;
        key.key_type = 1; /* string */
        memcpy(key.key_value, value, length);
        key.key_value[length] = 0;

        (void)hashTable.InsertOrAdd(&key);
    }
}

static char const *  rrtype_1_62[] = {
    "A",
    "NS",
    "MD",
    "MF",
    "CNAME",
    "SOA",
    "MB",
    "MG",
    "MR",
    "NULL",
    "WKS",
    "PTR",
    "HINFO",
    "MINFO",
    "MX",
    "TXT",
    "RP",
    "AFSDB",
    "X25",
    "ISDN",
    "RT",
    "NSAP",
    "NSAP-PTR",
    "SIG",
    "KEY",
    "PX",
    "GPOS",
    "AAAA",
    "LOC",
    "NXT",
    "EID",
    "NIMLOC",
    "SRV",
    "ATMA",
    "NAPTR",
    "KX",
    "CERT",
    "A6",
    "DNAME",
    "SINK",
    "OPT",
    "APL",
    "DS",
    "SSHFP",
    "IPSECKEY",
    "RRSIG",
    "NSEC",
    "DNSKEY",
    "DHCID",
    "NSEC3",
    "NSEC3PARAM",
    "TLSA",
    "SMIMEA",
    "Unassigned",
    "HIP",
    "NINFO",
    "RKEY",
    "TALINK",
    "CDS",
    "CDNSKEY",
    "OPENPGPKEY",
    "CSYNC"
};

static char const * rrtype_99_109[] = {
    "SPF",
    "UINFO",
    "UID",
    "GID",
    "UNSPEC",
    "NID",
    "L32",
    "L64",
    "LP",
    "EUI48",
    "EUI64"
};

static char const *  rrtype_249_258[] = {
    "TKEY",
    "TSIG",
    "IXFR",
    "AXFR",
    "MAILB",
    "MAILA",
    "RRCLASS * (ANY)",
    "URI",
    "CAA",
    "AVC"
};

static char const *  rrtype_32768_32769[] = {
    "TA",
    "DLV"
};

void DnsStats::PrintRRType(FILE * F, uint32_t rrtype)
{
    if (rrtype >= 1 && rrtype <= 62)
    {
        fprintf(F, """%s"",", rrtype_1_62[rrtype - 1]);
    }
    else if (rrtype >= 99 && rrtype <= 109)
    {
        fprintf(F, """%s"",", rrtype_99_109[rrtype - 99]);
    }
    else if (rrtype >= 249 && rrtype <= 258)
    {
        fprintf(F, """%s"",", rrtype_249_258[rrtype - 249]);
    }
    else if (rrtype >= 32768 && rrtype <= 32769)
    {
        fprintf(F, """%s"",", rrtype_32768_32769[rrtype - 32768]);
    }
    else if (rrtype >= 110 && rrtype <= 248)
    {
        fprintf(F, """Unassigned (%d)"",", rrtype);
    }
    else if (rrtype >= 110 && rrtype <= 248 ||
        rrtype >= 259 && rrtype <= 32767 ||
        rrtype >= 32770 && rrtype <= 65279)
    {
        fprintf(F, """Unassigned (%d)"",", rrtype);
    }
    else if (rrtype >= 65280 && rrtype <= 65534)
    {
        fprintf(F, """Private use (%d)"",", rrtype);
    }
    else
    {
        fprintf(F, """Reserved (%d)"",", rrtype);
    }

}

static char const *  rrclass_0_4[] = {
    "Reserved (0)",
    "Internet (IN)",
    "Unassigned (2)",
    "Chaos (CH)",
    "Hesiod (HS)"
};

static char const *  rrclass_254_255[] = {
    "QCLASS NONE",
    "QCLASS * (ANY)"
};

void DnsStats::PrintRRClass(FILE * F, uint32_t rrclass)
{
    if (rrclass <= 4)
    {
        fprintf(F, """%s"",", rrclass_0_4[rrclass]);
    }
    else if (rrclass >= 254 && rrclass <= 255)
    {
        fprintf(F, """%s"",", rrclass_254_255[rrclass - 254]);
    }
    else if (rrclass >= 5 && rrclass <= 253 ||
        rrclass >= 256 && rrclass <= 65279)
    {
        fprintf(F, """Unassigned (%d)"",", rrclass);
    }
    else if (rrclass >= 65280 && rrclass <= 65534)
    {
        fprintf(F, """Private use (%d)"",", rrclass);
    }
    else
    {
        fprintf(F, """Reserved (%d)"",", rrclass);
    }
}

static char const *  opcode_0_5[] = {
    "Query",
    "IQuery",
    "Status",
    "Unassigned (3)",
    "Notify",
    "Update"
};

void DnsStats::PrintOpCode(FILE * F, uint32_t opcode)
{
    if (opcode <= 5)
    {
        fprintf(F, """%s"",", opcode_0_5[opcode]);
    }
    else
    {
        fprintf(F, """Unassigned(%d)"",", opcode);
    }
}

static char const *  rcode_0_25[] = {
    "NoError",
    "FormErr",
    "ServFail",
    "NXDomain",
    "NotImp",
    "Refused",
    "YXDomain",
    "YXRRSet",
    "NXRRSet",
    "NotAuth",
    "NotZone",
    "Unassigned (11)",
    "Unassigned (12)",
    "Unassigned (13)",
    "Unassigned (14)",
    "Unassigned (15)",
    "BADVERS",
    "BADSIG",
    "BADKEY",
    "BADTIME",
    "BADMODE",
    "BADNAME",
    "BADALG",
    "BADTRUNC",
    "BADCOOKIE"
};

void DnsStats::PrintRCode(FILE * F, uint32_t rcode)
{
    if (rcode <= 25)
    {
        fprintf(F, """%s"",", rcode_0_25[rcode]);
    }
    else if (rcode >= 3841 && rcode <= 4095)
    {
        fprintf(F, """Private use (%d)"",", rcode);
    }
    else if (rcode == 65535)
    {
        fprintf(F, """Reserved (%d)"",", rcode);
    }
    else
    {
        fprintf(F, """Unassigned(%d)"",", rcode);
    }
}

static char const * dns_flags_id[] = {
    "CD",
    "AD",
    "bit 9",
    "RA",
    "RD",
    "TC",
    "AA"
};

void DnsStats::PrintDnsFlags(FILE * F, uint32_t flag)
{
    if (flag < 7)
    {
        fprintf(F, """%s"",", dns_flags_id[flag]);
    }
    else
    {
        fprintf(F, """ %d"",", flag);
    }
}

void DnsStats::PrintEDnsFlags(FILE * F, uint32_t flag)
{
    if (flag == 15)
    {
        fprintf(F, """DO"",");
    }
    else
    {
        fprintf(F, """ %d"",", 16 - flag);
    }
}

static char const * dnssec_algo_id_0_16[] = {
    "DELETE",
    "RSAMD5",
    "DH",
    "DSA",
    "Reserved (4)",
    "RSASHA1",
    "DSA-NSEC3-SHA1",
    "RSASHA1-NSEC3-SHA1",
    "RSASHA256",
    "Reserved (9)",
    "RSASHA512",
    "Reserved (11)",
    "ECC-GOST",
    "ECDSAP256SHA256",
    "ECDSAP384SHA384",
    "ED25519",
    "ED448"
};

static char const * dnssec_algo_id_252_254[] = {
    "INDIRECT",
    "PRIVATEDNS",
    "PRIVATEOID"
};

void DnsStats::PrintKeyAlgorithm(FILE * F, uint32_t algo)
{
    if (algo <= 16)
    {
        fprintf(F, """%s"",", dnssec_algo_id_0_16[algo]);
    }
    else if (algo >= 252 && algo <= 254)
    {
        fprintf(F, """%s"",", dnssec_algo_id_252_254[algo - 252]);
    }
    else if (algo >= 17 && algo <= 122)
    {
        fprintf(F, """unassigned (%d)"",", algo);
    }
    else if (algo >= 17 && algo <= 122)
    {
        fprintf(F, """reserved (%d)"",", algo);
    }
}

static char const * edns_option_0_14[] = {
    "Reserved (0)",
    "LLQ",
    "UL",
    "NSID",
    "Reserved",
    "DAU",
    "DHU",
    "N3U",
    "edns-client-subnet",
    "EDNS EXPIRE",
    "COOKIE",
    "edns-tcp-keepalive",
    "Padding",
    "CHAIN",
    "edns-key-tag"
};


void DnsStats::PrintOptOption(FILE * F, uint32_t option)
{
    if (option <= 14)
    {
        fprintf(F, """%s"",", edns_option_0_14[option]);
    }
    else if (option == 26946)
    {
        fprintf(F, """DeviceID"",");
    }
    else if (option >= 15 && option <= 26945 ||
        option >= 26947 && option <= 65000)
    {
        fprintf(F, """Unassigned (%d)"",", option);
    }
    else if (option >= 65001 && option <= 65534)
    {
        fprintf(F, """Experimental (%d)"",", option);
    }
    else
    {
        fprintf(F, """Reserved (%d)"",", option);
    }
}



/*
* Examine the packet level information
*
* - DNS OpCodes
* - DNS RCodes
* - DNS Header Flags
*
* Analyze queries and responses.
* Special cases for TXT, KEY, CSYNC
*

1  1  1  1  1  1
0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

void DnsStats::SubmitPacket(uint8_t * packet, uint32_t length)
{
    bool is_response;
    uint32_t flags = 0;
    uint32_t opcode = 0;
    uint32_t rcode = 0;
    uint32_t e_rcode = 0;
    uint32_t qdcount = 0;
    uint32_t ancount = 0;
    uint32_t nscount = 0;
    uint32_t arcount = 0;
    uint32_t parse_index = 0;

    if (length < 12)
    {
        return;
    }

    is_response = ((packet[2] & 128) != 0);
    flags = ((packet[2] & 7) << 4) | ((packet[3] & 15) >> 4);
    opcode = (packet[2] >> 3) & 15;
    rcode = (packet[3] & 15);
    qdcount = (packet[4] << 8) | packet[5];
    ancount = (packet[6] << 8) | packet[7];
    nscount = (packet[8] << 8) | packet[9];
    arcount = (packet[10] << 8) | packet[11];

    SubmitRegistryNumber(REGISTRY_DNS_OpCodes, opcode);

    for (uint32_t i = 0; i < 7; i++)
    {
        if ((flags & (1 << i)) != 0)
        {
            SubmitRegistryNumber(REGISTRY_DNS_Header_Flags, i);
        }
    }

    parse_index = 12;

    for (uint32_t i = 0; i < qdcount; i++)
    {
        parse_index = SubmitQuery(packet, length, parse_index);
    }

    for (uint32_t i = 0; i < ancount; i++)
    {
        parse_index = SubmitRecord(packet, length, parse_index, NULL);
    }

    for (uint32_t i = 0; i < nscount; i++)
    {
        parse_index = SubmitRecord(packet, length, parse_index, NULL);
    }

    for (uint32_t i = 0; i < arcount; i++)
    {
        parse_index = SubmitRecord(packet, length, parse_index, &e_rcode);
    }

    if (is_response)
    {
        rcode |= (e_rcode << 4);
        SubmitRegistryNumber(REGISTRY_DNS_RCODES, rcode);
    }

}

bool DnsStats::ExportToCsv(char * fileName)
{
    FILE* F;
    dns_registry_entry_t *entry;
#ifdef WINDOWS
    errno_t err = fopen_s(&F, fileName, "w");
    bool ret = (err == 0);
#else
    bool ret;

    F = fopen(fileName, "w");
    ret = (F != NULL);
#endif



    if (ret)
    {
        for (uint32_t i = 0; i < hashTable.GetSize(); i++)
        {
            entry = hashTable.GetEntry(i);

            if (entry != NULL)
            {
                if (entry->registry_id < RegistryNameByIdNb)
                {
                    fprintf(F, """%s"",", RegistryNameById[entry->registry_id]);
                }
                else
                {
                    fprintf(F, """%d"",", entry->registry_id);
                }
                
                if (entry->key_type == 0)
                {
                    fprintf(F, """%d"",", entry->key_number);
                }
                else
                {
                    fprintf(F, """%s,""", entry->key_value);
                }

                if (entry->registry_id == REGISTRY_DNS_RRType ||
                    entry->registry_id == REGISTRY_DNS_Q_RRType)
                {
                    PrintRRType(F, entry->key_number);
                }
                else if (entry->registry_id == REGISTRY_DNS_CLASSES ||
                    entry->registry_id == REGISTRY_DNS_Q_CLASSES)
                {
                    PrintRRClass(F, entry->key_number);
                }
                else if (entry->registry_id == REGISTRY_DNS_OpCodes)
                {
                    PrintOpCode(F, entry->key_number);
                }
                else if (entry->registry_id == REGISTRY_DNS_RCODES)
                {
                    PrintRCode(F, entry->key_number);
                }
                else if (entry->registry_id == REGISTRY_DNS_Header_Flags)
                {
                    PrintDnsFlags(F, entry->key_number);
                }
                else if (entry->registry_id == REGISTRY_EDNS_Header_Flags)
                {
                    PrintEDnsFlags(F, entry->key_number);
                }
                else if (entry->registry_id == REGISTRY_DNSSEC_Algorithm_Numbers)
                {
                    PrintKeyAlgorithm(F, entry->key_number);
                }
                else if (entry->registry_id == REGISTRY_EDNS_OPT_CODE)
                {
                    PrintOptOption(F, entry->key_number);
                }
                else 
                {
                    fprintf(F, """ "",");
                }

                fprintf(F, """%d""\n", entry->count);
            }
        }

        fclose(F);
    }


    return ret;
}

