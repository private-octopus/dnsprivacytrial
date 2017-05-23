// udpdnsrand.cpp : generation of random DNS requests.
//
// The idea is to generate random UDP packets and throw them
// at a DNS server.
// What is random?
// * the queried name, taken from a dictionary of name, or
//   including some proportion of "no such name".
// * Some queries will be against inverse DNS?
// * the query flags that make sense
// * presence of EDNS or not
// * the record type
// * the record class
// What are the goals?
// * explore queries besides simple A/AAAA.
//   in particular, get sufficient number of DNS KEY, OPT for further analysis.
// * accumulate new names as we learn them, e.g. from NS, MX, etc.
// * generate error codes so we can explore them.
// What are the issues?
// * SRV records: need to find some service type. Should this be specialized for DNS-SD?
// * truncation. Should this run over TCP?
// * bookkeeping. Should this use the same dns stats as pcap analyzer?
//

#include "stdafx.h"


int main()
{
    return 0;
}

