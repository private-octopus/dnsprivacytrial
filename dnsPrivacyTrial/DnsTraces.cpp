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
    errno_t er = fopen_s(&F, fname, "r");

    if (er != 0 || F == NULL)
    {
        ret = -1;
    }
    else
    {
        while (fgets(buffer, sizeof(buffer), F))
        {
            DnsDissectorLine * ds = DnsDissectorLine::CreateFromLine(buffer, sizeof(buffer));

            if (ds != NULL)
            {
                if (CheckAllocation(nb_records + 1))
                {
                    dnsSet[nb_records] = ds;
                    nb_records++;
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

/*
bool DnsTraces::CheckAllocation(int n)
{
    bool ret = true;

    if (nb_records_allocated < n)
    {
        int na = (nb_records_allocated == 0) ? 128 : nb_records_allocated;

        while (na < n)
        {
            na = 2 * na;
        }

        DnsDissectorLine ** newSet = new DnsDissectorLine*[na];

        if (newSet == NULL)
        {
            ret = false;
        }
        else
        {
            for (int i = 0; i < nb_records; i++)
            {
                newSet[i] = dnsSet[i];
                dnsSet[i] = NULL;
            }

            for (int i = nb_records; i < na; i++)
            {
                newSet[i] = NULL;
            }

            if (dnsSet != NULL)
            {
                delete[] dnsSet;
            }

            dnsSet = newSet;
        }
    }

    return ret;
}
*/
