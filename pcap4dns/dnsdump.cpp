#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../dnsPrivacyTrial/DnsTypes.h"
#include "DnsStats.h"
#include "dnsdump.h"



dnsdump::dnsdump()
{
}


dnsdump::~dnsdump()
{
}


int dnsdump::dns_name_dump(uint8_t * response, int response_length, int start)
{
    int l = 0;
    int offset = 0;
    int part_count = 0;
    int name_start = start;

    while (start < response_length && start >= 0)
    {
        if (part_count > 0)
            printf(".");
        part_count++;
        l = response[start];
        if (l == 0)
        {
            if (part_count == 1)
                printf(".");
            start++;
            break;
        }
        else if (l >= 0xC0)
        {
            if ((start + 2) > response_length)
            {
                start = response_length;
                printf("???");
                break;
            }
            else
            {
                /* Implement name reference by recursion */
                start++;
                offset = (l & 0x3F) | response[start];
                start++;
                if (offset < name_start)
                {
                    (void)dns_name_dump(response, response_length, offset);
                }
                else
                {
                    printf("...");
                }
                break;
            }
        }
        else
        {
            if (start + 1 + l >= response_length)
            {
                printf("error -- length(%d) >= %d - %d", l, response_length, start);
                start = response_length;
                break;
            }
            else
            {
                for (int i = 0; i < l; i++)
                {
                    int c = response[start + 1 + i];
                    if (c < 32 || c > 126)
                    {
                        c = '?';
                    }
                    printf("%c", c);
                }
            }
            start += l + 1;
        }
    }

    return start;
}

char * dnsdump::rr_type_string(int rr_type, char * buffer)
{
    char * rr_string = NULL;
    char* common_rr_string[16] = {
        "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG",
        "MR", "NULL", "WKS", "PTR", "HINFO", "MINFO", "MX", "TXT" };

    if (rr_type > 0)
    {
        if (rr_type <= 16)
        {
            rr_string = common_rr_string[rr_type - 1];
        }
        else switch (rr_type)
        {
        case DnsRtype_AAAA:
            rr_string = "AAAA";
            break;
        case DnsRtype_SRV:
            rr_string = "SRV";
            break;
        case DnsRtype_OPT:
            rr_string = "OPT";
            break;
        case DnsRtype_TSIG:
            rr_string = "TSIG";
            break;
        case DnsRtype_ANY:
            rr_string = "ANY";
            break;
        default:
            rr_string = itoa(rr_type, buffer, 10);
            break;
        }
    }
    return rr_string;
}

int dnsdump::query_dump(uint8_t* response, int response_length, int start)
{
    int rclass = 0;
    int rtype = 0;
    char buffer[16];
    /* print the name */
    printf("QNAME=");
    start = dns_name_dump(response, response_length, start);
    if ((start + 4) <= response_length)
    {
        rtype = (response[start] << 8) | response[start + 1];
        rclass = (response[start + 2] << 8) | response[start + 3];
        printf(" QTYPE=%s, ", rr_type_string(rtype, buffer));
        printf("QCLASS=%d%s\n", rclass & 0x7FFF, ((rclass & 0x8000) == 0) ? "" : "(flush)");
        start += 4;
    }
    else
    {
        printf("????\n");
        start = response_length;
    }
    return start;
}

int dnsdump::record_dump(uint8_t* response, int response_length, int start)
{
    int rtype = 0;
    int rclass = 0;
    unsigned int ttl = 0;
    int ldata = 0;
    int i = 0, j = 0;
    char buffer[16];

    /* print the name */
    printf("NAME=");
    start = dns_name_dump(response, response_length, start);
    if ((start + 10) <= response_length)
    {
        rtype = (response[start] << 8) | response[start + 1];
        rclass = (response[start + 2] << 8) | response[start + 3];
        ttl = (response[start + 4] << 24) | (response[start + 5] << 16)
            | (response[start + 6] << 8) | response[start + 7];
        ldata = (response[start + 8] << 8) | response[start + 9];
        printf(" RTYPE=%s, ", rr_type_string(rtype, buffer));
        printf("RCLASS=%d%s, ", rclass & 0x7FFF, ((rclass & 0x8000) == 0) ? "" : "(flush)");
        printf("TTL=%u, L=%d\n", ttl, ldata);
        start += 10;
        if (start + ldata <= response_length)
        {
            for (i = 0; i < ldata; i += 16)
            {
                printf("    ");
                for (int j = 0; j < 16; j++)
                {
                    int k = start + i + j;

                    if ((i + j) < ldata)
                    {
                        printf("%02x", response[k]);
                    }
                    else
                    {
                        printf("  ");
                    }
                    if ((j & 3) == 3)
                    {
                        printf(" ");
                    }
                }
                printf("   ");
                for (int j = 0; j < 15 && i < ldata; j++)
                {

                    int k = start + i + j;
                    int c = response[k];

                    if ((i + j) >= ldata)
                    {
                        break;
                    }

                    if (c < 32 || c >= 127)
                    {
                        c = '?';
                    }
                    printf("%c", c);
                    if ((j & 3) == 3)
                    {
                        printf(" ");
                    }
                }
                printf("\n");
            }
            start += ldata;
        }
        else
        {
            printf("    Error, %d + %d > %d\n", start, ldata, response_length);
            start = response_length;
        }
    }
    else
    {
        printf("????\n");
        start = response_length;
    }
    return start;
}

void dnsdump::dns_dump(uint8_t* response, int response_length)
{
    int qd_count = (response[4] << 8) | response[5];
    int an_count = (response[6] << 8) | response[7];
    int ar_count = (response[8] << 8) | response[9];
    int ad_count = (response[10] << 8) | response[11];
    int start = 12;
    int i;

    printf("Query_ID = %02x%02x, Opcode = %02x, Rcode = %02x\n",
        response[0], response[1], response[2], response[3]);
    printf("QDCOUNT = %d, ", qd_count);
    printf("ANCOUNT = %d, ", an_count);
    printf("ARCOUNT = %d, ", ar_count);
    printf("ADCOUNT = %d\n", ad_count);

    for (i = 0; i < qd_count; i++)
    {
        printf("QUERY[%d]: ", i + 1);
        start = query_dump(response, response_length, start);
    }

    for (i = 0; i < an_count; i++)
    {
        printf("ANSWER[%d]: ", i + 1);
        start = record_dump(response, response_length, start);
    }

    for (i = 0; i < ar_count; i++)
    {
        printf("AR[%d]: ", i + 1);
        start = record_dump(response, response_length, start);
    }

    for (i = 0; i < ad_count; i++)
    {
        printf("AD[%d]: ", i + 1);
        start = record_dump(response, response_length, start);
    }
}

#if 0
void dnsdump::message_dump(SOCKADDR* addr_from, uint8_t* response, int response_length)
{
    char text[256];
    int from_port;

    if (response_length > 0)
    {
        if (addr_from->sa_family == AF_INET)
        {
            text[0] = ']';
            (void)InetNtopA(addr_from->sa_family
                , &((SOCKADDR_IN *)addr_from)->sin_addr, &text[1], sizeof(text) - 1);
            strcat(text, "]");
            from_port = ntohs(((SOCKADDR_IN *)addr_from)->sin_port);
        }
        else if (addr_from->sa_family == AF_INET6)
        {
            (void)InetNtopA(addr_from->sa_family
                , &((SOCKADDR_IN6 *)addr_from)->sin6_addr, text, sizeof(text));
            from_port = ntohs(((SOCKADDR_IN6 *)addr_from)->sin6_port);
        }
        else
        {
            text[0] = '?';
            text[1] = '?';
            text[2] = '?';
            text[3] = 0;
            from_port = 0;
        }

        printf("Received %d bytes from %s:%d, time=%d\n"
            , response_length, text, from_port, gettime_millisec());

        for (int i = 0; i < response_length; i++)
        {
            printf("%02x", response[i]);
            if ((i & 31) == 31)
                printf("\n");
            else if ((i & 3) == 3)
                printf(" ");
        }
        printf("\n");

        dns_dump(response, response_length);
    }
}
#endif