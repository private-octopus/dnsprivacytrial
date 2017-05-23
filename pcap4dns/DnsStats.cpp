#include <stdlib.h>
#include <string.h>
#include <stdio.h>
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

    if (is_response)
    {
        SubmitRegistryNumber(REGISTRY_DNS_RCODES, rcode);
    }

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
        parse_index = SubmitRecord(packet, length, parse_index);
    }

    for (uint32_t i = 0; i < nscount; i++)
    {
        parse_index = SubmitRecord(packet, length, parse_index);
    }

    for (uint32_t i = 0; i < arcount; i++)
    {
        parse_index = SubmitRecord(packet, length, parse_index);
    }
}

char const * RegistryNameById[] = {
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
    "Q-RR Type"
};

uint32_t RegistryNameByIdNb = sizeof(RegistryNameById) / sizeof(char const*);

bool DnsStats::ExportToCsv(char * fileName)
{
    FILE* F;
    errno_t err = fopen_s(&F, fileName, "w");
    bool ret = (err == 0);
    dns_registry_entry_t *entry;

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

                if (entry->registry_id == REGISTRY_DNS_RRType ||
                    entry->registry_id == REGISTRY_DNS_Q_RRType)
                {
                    PrintRRType(F, entry->key_number);
                }
                else if (entry->registry_id == REGISTRY_DNS_Header_Flags)
                {
                    PrintDnsFlags(F, entry->key_number);
                }
                else if (entry->key_type == 0)
                {
                    fprintf(F, """%d"",", entry->key_number);
                }
                else
                {
                    fprintf(F, """%s,""", entry->key_value);
                }

                fprintf(F, """%d""\n", entry->count);
            }
        }

        fclose(F);
    }


    return ret;
}

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

int DnsStats::SubmitRecord(uint8_t * packet, uint32_t length, uint32_t start)
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
            if (ldata > 0)
            {
                /* only record rrtypes and rrclass if valid response */
                SubmitRegistryNumber(REGISTRY_DNS_CLASSES, rrclass);
                SubmitRegistryNumber(REGISTRY_DNS_RRType, rrtype);

                /* TODO: further parsing for KEY, OPT, AFSDB, NSEC3, DHCID, RSYNC types */
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

char *  rrtype_1_62[] = {
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

char *  rrtype_99_109[] = {
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

char *  rrtype_249_258[] = {
    "TKEY",
    "TSIG",
    "IXFR",
    "AXFR",
    "MAILB",
    "MAILA",
    "*",
    "URI",
    "CAA",
    "AVC"
};

char *  rrtype_32768_32769[] = {
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
    else
    {
        fprintf(F, """%d"",", rrtype);
    }
}

char * dns_flags_id[] = {
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