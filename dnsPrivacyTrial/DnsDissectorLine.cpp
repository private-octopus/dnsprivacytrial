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

#include "DnsDissectorLine.h"

DnsDissectorLine::DnsDissectorLine() 
    :
    number(0),
    time (0),
    source (NULL),
    destination(NULL),
    protocol(NULL),
    length(0),
    is_query(false),
    query_id(0),
    query_rtype(DnsRtype_UNEXPECTED),
    qname (NULL),
    cname_count(0),
    cname (NULL),
    a_val(NULL)
{
}

DnsDissectorLine::~DnsDissectorLine()
{
    Clear();
}

void DnsDissectorLine::Clear()
{

    number = 0;
    time = 0;
    if (source != NULL)
    {
        delete[] source;
        source = NULL;
    }

    if (destination != NULL)
    {
        delete[] destination;
        destination = NULL;
    }

    if (protocol != NULL)
    {
        delete[] protocol;
        protocol = NULL;
    }

    length = 0;
    is_query = 0;
    query_id = 0;
    query_rtype = DnsRtype_UNEXPECTED;

    if (qname != NULL)
    {
        delete[] qname;
        qname = NULL;
    }

    cname_count = 0;

    if (cname != NULL)
    {
        delete[] cname;
        cname = NULL;
    }

    if (a_val != NULL)
    {
        delete[] a_val;
        a_val = NULL;
    }
}

DnsDissectorLine * DnsDissectorLine::CreateFromLine(char * line, int linemax)
{
    DnsDissectorLine *ds = new DnsDissectorLine();

    if (ds != NULL)
    {
        (void)ds->ParseCsvLine(line, linemax);

        if (ds->number < 0 ||
            ds->time < 0 ||
            ds->source == NULL ||
            ds->destination == NULL ||
            ds->number < 0 ||
            ds->query_id < 0 ||
            ds->qname == NULL)
        {
            delete ds;
            ds = NULL;
        }
    }

    return ds;
}

int DnsDissectorLine::ParseCsvLine(char * line, int linemax)
{
    int position = 0;

    Clear();

    position = ParseNumber(line, linemax, position, &number);
    position = ParseTime(line, linemax, position, &time);
    position = ParseQuotedString(line, linemax, position, &source);
    position = ParseQuotedString(line, linemax, position, &destination);
    position = ParseQuotedString(line, linemax, position, &protocol);
    position = ParseNumber(line, linemax, position, &length);
    position = ParseDnsDissector(line, linemax, position);

    return position;
}

static char const * StandardQuery = "Standard query ";
static char const * StandardQueryResponse = "Standard query response ";

int DnsDissectorLine::ParseDnsDissector(char * line, int linemax, int position)
{
    position = SkipQuoteAndBlanks(line, linemax, position);

    position = ParseQueryType(line, linemax, position);
    position = ParseHexNumber(line, linemax, position, &query_id);
    position = ParseRType(line, linemax, position, &query_rtype);
    position = ParseSpacedString(line, linemax, position, &qname);

    cname = NULL;
    cname_count = 0;
    a_val = NULL;
    
    if (!is_query)
    {
        int last_cname_position = -1;
        int this_cname_position = -1;
        int cname_length = 0;
        DnsRtype next_rtype = DnsRtype_UNEXPECTED;

        cname_count = 0;

        while (position < linemax)
        {
            position = ParseRType(line, linemax, position, &next_rtype);
            if (next_rtype == DnsRtype_CNAME)
            {
                cname_count++;
                /* Keep the last cname in the chain */
                this_cname_position = SkipSpaces(line, linemax, position);
                position = SkipSpacedString(line, linemax, position, &cname_length);
                if (cname_length > 0)
                {
                    last_cname_position = this_cname_position;
                }
            }
            else if (next_rtype == DnsRtype_A || next_rtype == DnsRtype_AAAA)
            {
                /* keep the first address in the chain */
                position = ParseSpacedString(line, linemax, position, &a_val);
                break;
            }
            else
            {
                break;
            }
        }

        if (last_cname_position != -1)
        {
            (void)ParseSpacedString(line, linemax, last_cname_position, &cname);
        }


    }
    return 0;
}

int DnsDissectorLine::ParseQueryType(char * line, int linemax, int position)
{
    is_query = true;
    if (position < linemax)
    {
        if (strncmp(line + position, StandardQueryResponse, sizeof(StandardQueryResponse) - 1) == 0)
        {
            position += sizeof(StandardQueryResponse) - 1;
            is_query = false;
        }
        else if (strncmp(line + position, StandardQuery, sizeof(StandardQuery) - 1) == 0)
        {
            position += sizeof(StandardQuery) - 1;
            is_query = true;
        }
        else
        {
            position = linemax;
        }
    }

    return position;
}

int DnsDissectorLine::ParseHexNumber(char * line, int linemax, int position, int * v)
{
    int num = 0;
    int first_position;

    *v = -1;

    position = SkipSpaces(line, linemax, position);

    if (position + 2 < linemax && line[position] == '0' && line[position+1] >= 'x')
    {
        position += 2;
        first_position = position;
        while (position < linemax)
        {
            if (line[position] >= '0' && line[position] <= '9')
            {
                num = 16 * num + (line[position++] - '0');
            }
            else if (line[position] >= 'A' && line[position] <= 'Z')
            {
                num = 16 * num + 10 + (line[position++] - 'A');
            }
            else if (line[position] >= 'a' && line[position] <= 'z')
            {
                num = 16 * num + 10 + (line[position++] - 'a');
            }
            else
            {
                break;
            }
        }

        if (position < linemax && position > first_position && line[position] == ' ')
        {
            *v = num;
            position++;
        }
        else
        {
            position = linemax;
        }
    }
    else
    {
        position = linemax;
    }

    return position;
}

static struct dns_rtype_list {
    DnsRtype rtype;
    char const * rtype_name;
} rtype_list[] = {
    { DnsRtype_A, "A"},
    { DnsRtype_NS, "NS"}, 
    { DnsRtype_MD, "MD"},
    { DnsRtype_MF, "MF"}, 
    { DnsRtype_CNAME, "CNAME"}, 
    { DnsRtype_SOA , "SOA"}, 
    { DnsRtype_MB, "MB"}, 
    { DnsRtype_MG, "MG"}, 
    { DnsRtype_MR, "MR"}, 
    { DnsRtype_NULL, "RR"}, 
    { DnsRtype_WKS, "WKS"},
    { DnsRtype_PTR , "PTR"}, 
    { DnsRtype_HINFO, "HINFO"}, 
    { DnsRtype_MINFO, "MINFO"}, 
    { DnsRtype_MX, "MX"},
    { DnsRtype_TXT, "TXT"}, 
    { DnsRtype_AAAA, "AAAA"}, 
    { DnsRtype_SRV, "SRV"},
    { DnsRtype_OPT, "OPT"},
    { DnsRtype_TSIG, "TSIG"},
    { DnsRtype_ANY, "ANY"},
    { DnsRtype_UNEXPECTED, "UNEXPECTED" }
};

static int rtype_list_count = sizeof(rtype_list) / sizeof(struct dns_rtype_list);

int DnsDissectorLine::ParseRType(char * line, int linemax, int position, DnsRtype * v)
{
    int num = 0;
    int first_position;
    int nb_chars = -1;

    *v = DnsRtype_UNEXPECTED;

    first_position = SkipSpaces(line, linemax, position);
    position = SkipSpacedString(line, linemax, position, &nb_chars);

    if (nb_chars > 0)
    {
        for (int i = 0; i < rtype_list_count; i++)
        {
            if (strlen(rtype_list[i].rtype_name) == nb_chars &&
                strncmp(line + first_position, rtype_list[i].rtype_name, nb_chars) == 0)
            {
                *v = rtype_list[i].rtype;
                break;
            }
        }
    }

    return position;
}

const char * DnsDissectorLine::RTypeToText(DnsRtype v)
{
    char * s = (char *) "UNKNOWN";

    for (int i = 0; i < rtype_list_count; i++)
    {
        if (rtype_list[i].rtype == v)
        {
            s = (char *) rtype_list[i].rtype_name;
            break;
        }
    }

    return (const char *) s;
}

int DnsDissectorLine::ParseSpacedString(char * line, int linemax, int position, char ** s)
{
    int nb_chars = 0;
    int first_position = SkipSpaces(line, linemax, position);

    *s = NULL;

    if (position < linemax)
    {
        position = SkipSpacedString(line, linemax, first_position, &nb_chars);
    }

    if (nb_chars <= 0)
    {
        position = linemax;
    }
    else
    {
        *s = new char[nb_chars + 1];

        if (*s != NULL)
        {
#ifdef WINDOWS
            errno_t er = memcpy_s(*s, nb_chars + 1, &line[first_position], nb_chars);

            if (er != 0)
            {
                delete[] * s;
                *s = 0;
                position = linemax;
            }
            else
            {
                (*s)[nb_chars] = 0;
            }
#else
            memcpy(*s, &line[first_position], nb_chars);
            (*s)[nb_chars] = 0;
#endif
        }
    }

    return position;
}

int DnsDissectorLine::ParseNumber(char * line, int linemax, int position, int * v)
{
    int num = 0;
    int first_position;

    *v = -1;

    position = SkipQuoteAndBlanks(line, linemax, position);
    first_position = position;

    while (position < linemax && line[position] >= '0' && line[position] <= '9')
    {
        num = 10 * num + (line[position++] - '0');
    }

    if (position < linemax && position > first_position && line[position] == '"')
    {
        *v = num;
        position++;
    }
    else
    {
        position = linemax;
    }

    return position;
}

int DnsDissectorLine::ParseTime(char * line, int linemax, int position, long long * t)
{
    long long num = 0;
    long long mult = 1000000;
    int first_position;

    *t = -1;

    position = SkipQuoteAndBlanks(line, linemax, position);
    first_position = position;

    while (position < linemax && line[position] >= '0' && line[position] <= '9')
    {
        num = 10 * num + (line[position++] - '0');
    }

    if (position < linemax && position > first_position && line[position] == '.')
    {
        num *= mult;
        position++;

        while (mult > 0 && position < linemax && line[position] >= '0' && line[position] <= '9')
        {
            mult /= 10;

            num += (line[position++] - '0')*mult;
        }

        if (position < linemax && line[position] == '"')
        {
            *t = num;
            position++;
        }
        else
        {
            position = linemax;
        }
    }
    else
    {
        position = linemax;
    }

    return position;
}

int DnsDissectorLine::ParseQuotedString(char * line, int linemax, int position, char ** s)
{
    int nb_chars = 0;
    int first_position = SkipQuoteAndBlanks(line, linemax, position);

    *s = NULL;

    if (first_position < linemax)
    {
        position = SkipQuotedString(line, linemax, first_position, &nb_chars);
    }

    if (nb_chars <= 0)
    {
        position = linemax;
    }
    else
    {
        *s = new char[nb_chars + 1];

        if (*s != NULL)
        {
#ifdef WINDOWS
            errno_t er = memcpy_s(*s, nb_chars + 1, &line[first_position], nb_chars);

            if (er != 0)
            {
                delete[] * s;
                *s = 0;
                position = linemax;
            }
            else
            {
                (*s)[nb_chars] = 0;
            }
#else
            memcpy(*s, &line[first_position], nb_chars);
            (*s)[nb_chars] = 0;
#endif
        }
    }

    return position;
}

int DnsDissectorLine::SkipQuotedString(char * line, int linemax, int position, int * nb_chars)
{
    int first = position;

    *nb_chars = -1;

    while (position < linemax && line[position] != 0)
    {
        if (line[position] == '"')
        {
            if (position + 1 < linemax && line[position + 1] == '"' )
            {
                position += 2;
            }
            else
            {
                *nb_chars = position - first;
                position++;
                break;
            }
        }
        else
        {
            position++;
        }
    }

    return position;
}

int DnsDissectorLine::SkipSpacedString(char * line, int linemax, int position, int * nb_chars)
{
    int first = position;

    *nb_chars = -1;

    while (position < linemax && line[position] != 0)
    {
        if (line[position] == ' ' || line[position] == '"')
        {
            *nb_chars = position - first;
            position++;
            break;
        }
        else
        {
            position++;
        }
    }

    return position;
}

int DnsDissectorLine::SkipSpaces(char * line, int linemax, int position)
{
    while (position < linemax && line[position] != 0 &&
        (line[position] == ' ' || line[position] == '\t'))
    {
        position++;
    }

    return position;
}

int DnsDissectorLine::SkipQuoteAndBlanks(char * line, int linemax, int position)
{
    while (position < linemax && line[position] != 0) 
    {
        if (line[position] == '"')
        {
            position++;
            break;
        }
        else if (line[position] == ' ' || line[position] == '\t' || line[position] == ',')
        {
            position++;
        }
        else
        {
            position = linemax;
        }
    }

    return position;
}