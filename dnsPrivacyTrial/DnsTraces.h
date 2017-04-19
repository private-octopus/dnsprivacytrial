#pragma once
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

