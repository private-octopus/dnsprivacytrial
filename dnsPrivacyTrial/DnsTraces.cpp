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
#include <stdio.h>
#include "DnsTracesUtil.h"
#include "DnsTraces.h"


DnsTraces::DnsTraces()
    :
    nb_records(0),
    nb_records_allocated(0),
    dnsSet(NULL)
{
}


DnsTraces::~DnsTraces()
{
    TArrayDelete<DnsDissectorLine>(dnsSet, nb_records); 
    dnsSet = NULL;
}

int DnsTraces::AddTraces(char * fname)
{
    int ret = 0;
    FILE * F;
    char buffer[1024];
#ifdef WINDOWS
    errno_t er = fopen_s(&F, fname, "r");
    if (er != 0 || F == NULL)
    {
        ret = -1;
    }
#else
    F = fopen(fname, "r");
    if (F == NULL)
    {
        ret = -1;
    }
#endif
    else
    {
        while (fgets(buffer, sizeof(buffer), F))
        {
            DnsDissectorLine * ds = DnsDissectorLine::CreateFromLine(buffer, sizeof(buffer));

            if (ds != NULL)
            {
                if (CheckAllocation(nb_records + 1))
                {
                    DnsTransaction * tr = new DnsTransaction();

                    dnsSet[nb_records] = ds;
                    nb_records++;

                    tr->InitializeFromTrace(ds);

                    transactions.InsertOrMerge(tr);
                }
                else
                {
                    delete ds;
                    ret = -1;
                    break;
                }
            }
        }

        fclose(F);
    }

    return ret;
}

int DnsTraces::SaveTransactionsToCsv(char * fname)
{
    int ret = 0;
    FILE * F;
#ifdef WINDOWS
    errno_t er = fopen_s(&F, fname, "w");

    if (er != 0 || F == NULL)
    {
        ret = -1;
    }
#else
    F = fopen(fname, "w");
    if (F == NULL)
    {
        ret = -1;
    }
    else
#endif
    else
    {
        DnsTransaction::PrintCsvFileHeader(F);

        for (unsigned int i = 0; i < transactions.TableSize(); i++)
        {
            if (transactions.HashTable()[i] != NULL)
            {
                (void)transactions.HashTable()[i]->PrintToCsvFile(F);
            }
        }
        fclose(F);
    }

    return ret;
}

DnsDissectorLine ** DnsTraces::getTraces()
{
    return dnsSet;
}

int DnsTraces::getNbTraces()
{
    return nb_records;
}

bool DnsTraces::CheckAllocation(int n)
{
    return CheckArrayAllocation<DnsDissectorLine>(n,
        &nb_records_allocated, nb_records, &dnsSet);
}

