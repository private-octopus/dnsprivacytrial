#ifndef DNSSTAT_H
#define DNSSTAT_H

#include <stdint.h>
#include <stdio.h>

/*
 * List of registry definitions 
 */

#define	REGISTRY_DNS_CLASSES	1
#define	REGISTRY_DNS_RRType	2
#define	REGISTRY_DNS_OpCodes	3
#define	REGISTRY_DNS_RCODES	4
#define	REGISTRY_DNS_AFSDB_RRSubtype	5
#define	REGISTRY_DNS_DHCID_RRIdType	6
#define	REGISTRY_DNS_LabelType	7
#define	REGISTRY_EDNS_OPT_CODE	8
#define	REGISTRY_DNS_Header_Flags	9
#define	REGISTRY_EDNS_Header_Flags	10
#define	REGISTRY_EDNS_Version_number	11
#define	REGISTRY_DNS_CSYNC_Flags	12
#define	REGISTRY_DNSSEC_Algorithm_Numbers	13
#define	REGISTRY_DNSSEC_KEY_Prime_Lengths	14
#define	REGISTRY_DNS_Q_CLASSES	15
#define	REGISTRY_DNS_Q_RRType	16
#define	REGISTRY_DNSSEC_KEY_Well_Known_Primes	17
#define	REGISTRY_EDNS_Packet_Size 18
#define	REGISTRY_DNS_Query_Size 19
#define	REGISTRY_DNS_Response_Size 20
#define	REGISTRY_DNS_TC_length 21

/*
 * Accumulate statistics:
 * 
 * Statistics are of the form "Registry, Key value, counter". These are maintained
 * in a big hash table, initialized to nothing at the beginning of the run. Each
 * packet that we parse provides some entries of the form "Registry, Key Value, 1 occurence". 
 * If the value is present in the hash base, increment the counter, else, 
 * create the entry.
 *
 * At the end of the run, write the values in CSV file. 
 */

typedef struct dns_registry_entry_s {
    uint32_t hash;
    uint32_t registry_id;
    uint32_t count;
    uint32_t key_type;
    uint32_t key_length;
    union {
        uint32_t key_number;
        uint8_t key_value[64];
    };
} dns_registry_entry_t;

class DnsStatHash
{
public:
    DnsStatHash();
    ~DnsStatHash();

    bool Resize(unsigned tableSize);
    bool InsertOrAdd(dns_registry_entry_t * key, bool need_alloc=true);

    uint32_t GetCount();

    uint32_t GetSize();

    dns_registry_entry_t * GetEntry(uint32_t indx);

private:
    uint32_t tableSize;
    uint32_t tableCount;
    dns_registry_entry_t ** hashTable;

    void Clear();
    bool DoInsert(dns_registry_entry_t * key, bool need_alloc);
    static uint32_t ComputeHash(dns_registry_entry_t * key);
    static bool IsSameKey(dns_registry_entry_t * key1, dns_registry_entry_t * key2);
};

class DnsStats
{
public:
    DnsStats();
    ~DnsStats();

    DnsStatHash hashTable;

    void SubmitPacket(uint8_t * packet, uint32_t length);

    bool ExportToCsv(char* fileName);

private:
    int SubmitQuery(uint8_t * packet, uint32_t length, uint32_t start);
    int SubmitRecord(uint8_t * packet, uint32_t length, uint32_t start, uint32_t * e_rcode, uint32_t * e_length);
    int SubmitName(uint8_t * packet, uint32_t length, uint32_t start);

    void SubmitOPTRecord(uint32_t flags, uint8_t * content, uint32_t length, uint32_t * e_rcode);
    void SubmitKeyRecord(uint8_t * content, uint32_t length);
    void SubmitRRSIGRecord(uint8_t * content, uint32_t length);
    void SubmitDSRecord(uint8_t * content, uint32_t length);

    void SubmitRegistryNumber(uint32_t registry_id, uint32_t number);
    void SubmitRegistryString(uint32_t registry_id, uint32_t length, uint8_t * value);

    void PrintRRType(FILE* F, uint32_t rrtype);
    void PrintRRClass(FILE* F, uint32_t rrclass);
    void PrintOpCode(FILE* F, uint32_t opcode);
    void PrintRCode(FILE* F, uint32_t rcode);
    void PrintDnsFlags(FILE* F, uint32_t flag);
    void PrintEDnsFlags(FILE* F, uint32_t flag);
    void PrintKeyAlgorithm(FILE* F, uint32_t algo);
    void PrintOptOption(FILE* F, uint32_t option);

};

#endif /* DNSTAT_H */
