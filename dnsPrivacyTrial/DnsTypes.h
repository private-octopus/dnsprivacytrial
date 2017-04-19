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