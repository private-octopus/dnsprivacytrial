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

// dnsPrivacyTrial.cpp
// Simple application that parses Wireshark captures, 
// filtered as DNS and exported as CSV version of the DNS dissector.
// From there, performs a set of analyzes:
// * Traffic characterization: frequency of queries, arrival model.
// * Service characterization: distribution of response times.
// * Name list: what is exposed in the list of queried names.
// * Privacy delta characterization: difference of information between the name and the corresponding IP.
//

#ifdef WIN32
#include "stdafx.h"
#endif
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
    char * oname = "TestOutput.csv";

    if (argc >= 2)
    {
        fname = argv[1];
    }

    if (argc >= 3)
    {
        oname = argv[2];
    }

    int ret = dt.AddTraces(fname);

    printf("Loaded %d traces from %s, ret = %d\n", dt.getNbTraces(), fname, ret);

    ret = dt.SaveTransactionsToCsv(oname);

    printf("Saved transactions to %s, ret = %d\n", oname, ret);

    return 0;
}

