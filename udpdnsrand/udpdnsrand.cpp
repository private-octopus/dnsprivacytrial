// udpdnsrand.cpp : generation of random DNS requests.
//
// The idea is to generate random UDP packets and throw them
// at a DNS server.
// What is random?
// * the queried name, taken from a dictionary of name, or
//   including some proportion of "no such name".
// * Some queries will be against inverse DNS?
// * the query flags that make sense
// * presence of EDNS or not
// * the record type
// * the record class
// What are the goals?
// * explore queries besides simple A/AAAA.
//   in particular, get sufficient number of DNS KEY, OPT for further analysis.
// * accumulate new names as we learn them, e.g. from NS, MX, etc.
// * generate error codes so we can explore them.
// What are the issues?
// * SRV records: need to find some service type. Should this be specialized for DNS-SD?
// * truncation. Should this run over TCP?
// * bookkeeping. Should this use the same dns stats as pcap analyzer?
//

#ifdef WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <assert.h>
#include "stdafx.h"
#include <stdint.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#ifndef SOCKET_TYPE 
#define SOCKET_TYPE SOCKET
#endif

#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) closesocket(x)
#endif
#ifndef WSA_START_DATA
#define WSA_START_DATA WSADATA
#endif
#ifndef WSA_START
#define WSA_START(x, y) WSAStartup((x), (y))
#endif
#else
/*
 * Alternate definition for the Unix port.
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#ifndef SOCKET_TYPE 
#define SOCKET_TYPE int
#endif
#ifndef INVALID_SOCKET 
#define INVALID_SOCKET -1
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) close(x)
#endif
#ifndef WSA_START_DATA
#define WSA_START_DATA int
#endif
#ifndef WSA_START
#define WSA_START(x, y) (*y = 0, true)
#endif
#ifndef InetPtonA
#define InetPtonA inet_pton
#endif
#endif

#include "DomainList.h"
#include "DnsGenRandom.h"

#define DNS_SERVER_PORT 53

int main(int argc, char ** argv)
{
    char * dictionary_name = (char *) "domains.csv";
    DomainList domainList;
    DnsGenRandom domainGen(&domainList);
    char * ip_address_text = (char *) "192.168.1.254";
    struct sockaddr_storage server_address;
    struct sockaddr_storage addr_from;
    socklen_t from_length = 0;
    struct sockaddr_in * ipv4_dest = (struct sockaddr_in *)&server_address;
    struct sockaddr_in6 * ipv6_dest = (struct sockaddr_in6 *)&server_address;
    int nb_packets = 16;
    int nb_packets_sent = 0;
    int nb_time_out = 0;
    int nb_names = 0;
    SOCKET_TYPE fd = INVALID_SOCKET;
    WSA_START_DATA wsaData;
    int nb_packets_in_transit = 0;
    fd_set   readfds;
    fd_set   writefds;
    fd_set * write_or_null_fds;
    struct timeval tv;
    int ret_select = 0;
    int bytes_recv = 0;
    int bytes_sent = 0;
    uint32_t packet_length = 0;
    uint8_t buffer[1500];
    bool ret = true;

    /* Get the parameters */
    if (argc > 1)
    {
        dictionary_name = argv[1];

        if (argc > 2)
        {
            ip_address_text = argv[2];

            if (argc > 3)
            {
                nb_packets = atoi(argv[3]);

                if (nb_packets <= 0)
                {
                    fprintf(stderr, "Invalid number of packets: %s\n", argv[3]);
                    ret = false;
                }

                if (argc > 4)
                {
                    nb_names = atoi(argv[4]);

                    if (nb_names <= 0)
                    {
                        fprintf(stderr, "Invalid number of names: %s\n", argv[4]);
                        ret = false;
                    }
                }
            }
        }
    }

    // Init WSA.
    if (ret)
    {
        if (WSA_START(MAKEWORD(2, 2), &wsaData)) {
            fprintf(stderr, "Cannot init WSA\n");
            ret = false;
        }
    }

    /* get the IP address of the server */
    if (ret)
    {
        memset(&server_address, 0, sizeof(server_address));

        if (InetPtonA(AF_INET, ip_address_text, &ipv4_dest->sin_addr) == 1)
        {
            /* Valid IPv4 address */
            ipv4_dest->sin_family = AF_INET;
            ipv4_dest->sin_port = htons(DNS_SERVER_PORT);
        }
        else if (InetPtonA(AF_INET6, ip_address_text, &ipv6_dest->sin6_addr) == 1)
        {
            /* Valid IPv6 address */
            ipv6_dest->sin6_family = AF_INET6;
            ipv6_dest->sin6_port = htons(DNS_SERVER_PORT);
        }
        else
        {
            fprintf(stderr, "Could not parse the address: %s\n", ip_address_text);
            ret = false;
        }
    }
    /* Load the dictionary */
    if (ret)
    {
        if (!domainList.Init(dictionary_name, nb_names))
        {
            fprintf(stderr, "Could not read the domain list: %s\n", dictionary_name);
            ret = false;
        }
    }

    /* Open a UDP socket */
    if (ret)
    {
        fd = socket(server_address.ss_family, SOCK_DGRAM, IPPROTO_UDP);
        ret = (fd != INVALID_SOCKET);
    }

        /* Generate the required number of packets,
         * checking responses or timers so no more than 8 are in transit */
    while (ret && nb_packets_sent < nb_packets)
    {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_SET(fd, &readfds);

        if (nb_packets_in_transit < 8)
        {
            FD_SET(fd, &writefds);
            write_or_null_fds = &writefds;
        }
        else
        {
            write_or_null_fds = NULL;
        }
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        select(fd, &readfds, write_or_null_fds, NULL, &tv);

        if (FD_ISSET(fd, &readfds))
        {
            /* Read the incoming response */
            from_length = sizeof(addr_from);
            bytes_recv = recvfrom(fd, (char*)buffer, sizeof(buffer), 0,
                (struct sockaddr *)&addr_from, &from_length);
            if (bytes_recv > 0)
            {
                /* cancel the time out count */
                nb_time_out = 0;
                /* Decrease the pending count */
                if (nb_packets_in_transit > 0)
                {
                    nb_packets_in_transit--;
                }
                /* TODO: statistics. */
                if (nb_packets_sent < 16)
                {
                    fprintf(stderr, "Received %d bytes\n", bytes_recv);
                }
            }
            else
            {
                fprintf(stderr, "Cannot receive a response from %s:53!\n",
                    ip_address_text);
                ret = false;
                break;
            }
        }
        else if (write_or_null_fds != NULL && FD_ISSET(fd, &writefds))
        {
            if (domainGen.GenerateQuery(buffer, sizeof(buffer), &packet_length))
            {
                bytes_sent = sendto(fd, (char*)buffer, packet_length, 0,
                    (const sockaddr *)&server_address,
                    (server_address.ss_family == AF_INET) ?
                    sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
                if (bytes_sent > 0)
                {
                    nb_packets_sent++;
                    nb_packets_in_transit++;
                    if (nb_packets_sent <= 16)
                    {
                        fprintf(stderr, "Sent %d bytes to %s:53.\n",
                            bytes_sent, ip_address_text);
                    }
                }
                else
                {
                    fprintf(stderr, "Cannot send %d bytes to %s:53!\n",
                        packet_length, ip_address_text);
                    ret = false;
                }
            }
            else
            {
                fprintf(stderr, "Could not generate random query from %s!\n",
                    dictionary_name);
                ret = false;
            }
        }
        else
        {
            nb_time_out++;
            if (nb_time_out > 5)
            {
                /* Got 5 consecutive time outs. This is bad. */
                fprintf(stderr, "Could not get responses from %s:53 after %d timeouts!\n",
                    ip_address_text, nb_time_out);
                ret = false;
            }
            else
            {
                /* give it a chance, try something else */
                nb_packets_in_transit--;
            }
        }
    }
 

    if (fd != INVALID_SOCKET)
    {
        SOCKET_CLOSE(fd);
    }

    if (!ret)
    {
        fprintf(stderr, "Usage: %s [<domain name file> [<ipv4 or ipv6 address> [<nbpackets>]]]\n", argv[0]);
    }

    return 0;
}

