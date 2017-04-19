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

class DnsTransaction
{
public:
    DnsTransaction();
    ~DnsTransaction();

    int Hash();
    bool Compare(DnsTransaction * key);
    DnsTransaction * Merge(DnsTransaction * key);
};

