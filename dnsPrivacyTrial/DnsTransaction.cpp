
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include "DnsTracesUtil.h"
#include "DnsTransaction.h"



DnsTransaction::DnsTransaction()
    :
    clientIp(NULL),
    serverIp(NULL),
    query_id(0),
    initial_time(0),
    query_name(NULL),
    query_rtype(DnsRtype_UNEXPECTED),
    nb_repeats(0),
    last_repeat_time(0),
    nb_response(0),
    first_response_time(0),
    cname_count(0),
    cname(NULL),
    query_length(0),
    response_length(0)
{
}

DnsTransaction::~DnsTransaction()
{
    if (clientIp != NULL)
    {
        delete[] clientIp;
    }

    if (serverIp != NULL)
    {
        delete[] clientIp;
    }

    if (query_name != NULL)
    {
        delete[] query_name;
    }

    if (cname != NULL)
    {
        delete[] cname;
    }
}

void DnsTransaction::InitializeFromTrace(DnsDissectorLine * trace)
{
    query_id = trace->Query_id();
    query_name = CopyString(trace->Qname());
    query_rtype = trace->Query_rtype();

    if (trace->Is_query())
    {
        clientIp = CopyString(trace->Source());
        serverIp = CopyString(trace->Destination());
        initial_time = trace->Time();
        last_repeat_time = initial_time;
        query_length = trace->Length();
        nb_repeats = 1;
    }
    else
    {
        clientIp = CopyString(trace->Destination());
        serverIp = CopyString(trace->Source());
        nb_response = 1;
        first_response_time = trace->Time();
        cname_count = trace->Cname_count();
        cname = CopyString(trace->Cname());
        a_val = CopyString(trace->A_val());
        response_length = trace->Length();
    }
}

int DnsTransaction::Hash()
{
    int h = 0xDEADBEEF;

    h = BasicHash(h, clientIp);
    h = BasicHash(h, serverIp);
    h = BasicHash(h, query_id);
    h = BasicHash(h, query_name);
    h = BasicHash(h, (int) query_rtype);

    return h;
}

bool DnsTransaction::Compare(DnsTransaction * key)
{
    bool ret = (
        query_id == key->query_id &&
        query_rtype == key->query_rtype &&
        strcmp(clientIp, key->clientIp) == 0 &&
        strcmp(serverIp, key->serverIp) == 0 &&
        strcmp(query_name, key->query_name) == 0);
    return ret;
}

void DnsTransaction::Merge(DnsTransaction * key)
{
    if (key->nb_repeats > 0)
    {
        if (nb_repeats == 0)
        {
            initial_time = key->initial_time;
            query_length = key->query_length;
            nb_repeats = key->nb_repeats;
        }
        else
        {
            initial_time = std::min(initial_time, key->initial_time);
            nb_repeats += key->nb_repeats;
            last_repeat_time = std::max(last_repeat_time, key->last_repeat_time);
        }
    }

    if (key->nb_response > 0)
    {
        if (nb_response == 0)
        {
            nb_response = key->nb_response;
            first_response_time = key->first_response_time;
            cname_count = key->cname_count;
            cname = key->cname;
            key->cname = NULL; 
            a_val = key->a_val;
            key->a_val = NULL;
            response_length = key->response_length;
        }
        else
        {
            first_response_time = std::min(first_response_time, key->first_response_time);
            nb_response += key->nb_response;
        }
    }

    delete key;
}
