#pragma once
/*
 * This is the result from a DNS analysis.
 * A transaction is defined by:
 * - Client IP
 * - Server IP
 * - Query ID
 * - Initial date
 * - Query name
 * - RType
 * - Number of repeat of the same query.
 * - Total repeat delays
 * - Response time, i.e. time from initial query to response.
 * - Number of CNAME
 * - Final CNAME
 * - Address found
 * This is obtained by merging several traces into a single list.
 */
#include <stdio.h>
#include "DnsTypes.h"
#include "DnsDissectorLine.h"

class DnsTransaction
{
public:
    DnsTransaction();
    ~DnsTransaction();

    void InitializeFromTrace(DnsDissectorLine * trace);

    unsigned int Hash();
    bool Compare(DnsTransaction * key);
    void Merge(DnsTransaction * key);

    static void PrintCsvFileHeader(FILE* F);
    int PrintToCsvFile(FILE* F) const;

private:
    char * clientIp;
    char * serverIp;
    int query_id;
    long long initial_time;
    char * query_name;
    DnsRtype query_rtype;
    int nb_repeats;
    long long last_repeat_time;
    int nb_response;
    long long  first_response_time;
    int cname_count;
    char * cname;
    int query_length;
    int response_length;
    char * a_val;
};

