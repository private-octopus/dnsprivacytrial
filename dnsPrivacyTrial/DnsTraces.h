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

#ifndef DNSTRACES_H
#define DNSTRACES_H

#include "DnsDissectorLine.h"
#include "DnsTransaction.h"
#include "DnsTracesUtil.h"

/*
 * DNS Traces is a simple copy of the data in the file, enabling processing.
 *
 * One of these processings is a statistical analysis of time arrival for queries,
 * which is meant as a traffic model. The analysis requires matching queries,
 * repetitions and responses. 
 *
 * When a new query is discovered (in Add Traces) it is checked against the
 * list of pending transactions. No avoid O(N^2) complexity, the transactions are
 * kept in a hash table. If there is no match, a new transaction is created; if
 * there is a match, the existing transaction is updated. For simplicity, we
 * assume that matches can only happen within one trace file.
 */
class DnsTraces
{
public:
    DnsTraces();
    ~DnsTraces();

    int AddTraces(char * fname);
    int SaveTransactionsToCsv(char * fname);

    DnsDissectorLine ** getTraces();
    int getNbTraces();

private:
    int nb_records;
    int nb_records_allocated;
    int nb_transactions;
    int nb_transactions_allocated;

    DnsDissectorLine ** dnsSet;
    THashTable<DnsTransaction> transactions;

    bool CheckAllocation(int n);
    bool CheckTransactionAllocation(int n);
};

#endif /* DNSTRACES_H */
