/*
* Copyright (c) 2017, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef DNSTRANSACTION_H
#define DNSTRANSACTION_H
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
    char * cdn_name;
};

#endif /* DNSTRANSACTION_H */
