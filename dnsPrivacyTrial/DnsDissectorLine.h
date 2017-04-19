#pragma once

enum DnsRtype {
    DnsRtype_A = 1, /* a host address */
    DnsRtype_NS = 2, /* an authoritative name server */
    DnsRtype_MD = 3, /* a mail destination (Obsolete - use MX) */
    DnsRtype_MF = 4, /* a mail forwarder (Obsolete - use MX) */
    DnsRtype_CNAME = 5, /* the canonical name for an alias */
    DnsRtype_SOA = 6, /* marks the start of a zone of authority */
    DnsRtype_MB = 7, /* a mailbox domain name (EXPERIMENTAL) */
    DnsRtype_MG = 8, /* a mail group member (EXPERIMENTAL) */
    DnsRtype_MR = 9, /* a mail rename domain name (EXPERIMENTAL) */
    DnsRtype_NULL = 10, /* a null RR (EXPERIMENTAL) */
    DnsRtype_WKS = 11, /* a well known service description */
    DnsRtype_PTR = 12, /* a domain name pointer */
    DnsRtype_HINFO = 13, /* host information */
    DnsRtype_MINFO = 14, /* mailbox or mail list information */
    DnsRtype_MX = 15, /* mail exchange */
    DnsRtype_TXT = 16, /* text strings */
    DnsRtype_AAAA = 28, /* Service record */
    DnsRtype_SRV = 33, /* Service record */
    DnsRtype_OPT = 41, /* EDNS0 OPT record */
    DnsRtype_TSIG = 250, /* Transaction Signature */
    DnsRtype_ANY = 255, /*Not a DNS type, but a DNS query type, meaning "all types"*/
    DnsRtype_UNEXPECTED = 0 /*Not a DNS type, indicates a parsing error */
};

class DnsDissectorLine
{
public:
    DnsDissectorLine();
    ~DnsDissectorLine();

    void Clear();

    static DnsDissectorLine * CreateFromLine(char * line, int linemax);

    int ParseCsvLine(char * line, int linemax);

private:
    int number;
    long long time;
    char * source;
    char * destination;
    char * protocol;
    int length;
    bool is_query;
    int query_id;
    DnsRtype query_rtype;
    char * qname;
    int cname_count;
    char * cname; 
    char * a_val;

    int ParseDnsDissector(char * line, int linemax, int position);
    int ParseQueryType(char * line, int linemax, int position);
    int ParseHexNumber(char * line, int linemax, int position, int * v); 
    static int ParseRType(char * line, int linemax, int position, DnsRtype * v);
    int ParseSpacedString(char * line, int linemax, int position, char ** s);

    static int SkipSpacedString(char * line, int linemax, int position, int * nb_chars);

    static int ParseNumber(char * line, int linemax, int position, int * v);
    static int ParseTime(char * line, int linemax, int position, long long * t);
    static int ParseQuotedString(char * line, int linemax, int position, char ** s);

    static int SkipQuotedString(char * line, int linemax, int position, int * nb_chars);
    static int SkipSpaces(char * line, int linemax, int position);
    static int SkipQuoteAndBlanks(char * line, int linemax, int position);

};

