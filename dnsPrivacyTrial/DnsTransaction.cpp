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
    response_length(0),
    a_val(NULL)
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
        delete[] serverIp;
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

unsigned int DnsTransaction::Hash()
{
    unsigned int h = 0xDEADBEEF;

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

void DnsTransaction::PrintCsvFileHeader(FILE * F)
{
    fprintf(F, "clientIp, serverIp, query_id, initial_time, query_name, query_rtype, ");
    fprintf(F, "nb_repeats, last_repeat_time, nb_response, first_response_time, ");
    fprintf(F, "cname_count, cname, query_length, response_length, a_val, response_time, repeat_time\n");
}

int DnsTransaction::PrintToCsvFile(FILE * F) const
{
    const char * rtype_name = DnsDissectorLine::RTypeToText(query_rtype);
    int ret = fprintf(F,
        """%s"",""%s"",""%d"",""%lld"",""%s"",""%s"",""%d"",""%lld"",""%d"",""%lld"",""%d"",""%s"",""%d"",""%d"",""%s"", ""%lld"", ""%lld""\n",
        clientIp, serverIp, query_id, initial_time, query_name, rtype_name,
        nb_repeats, last_repeat_time, nb_response, first_response_time,
        cname_count, (cname == NULL) ? "" : cname, query_length, response_length,
        (a_val == NULL) ? "" : a_val, 
        (first_response_time > 0)? first_response_time- initial_time:0,
        (last_repeat_time > 0) ? last_repeat_time - initial_time : 0);


    return (ret > 0)?0:-1;
}
