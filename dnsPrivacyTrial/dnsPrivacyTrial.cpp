// dnsPrivacyTrial.cpp
// Simple application that parses Wireshark captures, 
// filtered as DNS and exported as CSV version of the DNS dissector.
// From there, performs a set of analyzes:
// * Traffic characterization: frequency of queries, arrival model.
// * Service characterization: distribution of response times.
// * Name list: what is exposed in the list of queried names.
// * Privacy delta characterization: difference of information between the name and the corresponding IP.
//

#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "DnsDissectorLine.h"
#include "DnsTraces.h"

/*
* Example of lines:
* "174","81.563115","192.168.1.100","192.168.1.254","DNS","72","Standard query 0x6e9f A api.bing.com"
* "175","81.566599","192.168.1.254","192.168.1.100","DNS","164","Standard query response 0x238a A www.bing.com CNAME www-bing-com.a-0001.a-msedge.net CNAME a-0001.a-msedge.net A 204.79.197.200 A 13.107.21.200"
* "191","81.608640","192.168.1.254","192.168.1.100","DNS","139","Standard query response 0x0141 AAAA a-0001.a-msedge.net SOA ns1.a-msedge.net"
*/

int main(int argc, char* argv[])
{

    DnsTraces dt;
    char * fname = "TestInput.txt";

    if (argc >= 2)
    {
        fname = argv[1];
    }

    int ret = dt.AddTraces(fname);

    printf("Loaded %d traces from %s, ret = %d\n", dt.getNbTraces(), fname, ret);

    return 0;
}

