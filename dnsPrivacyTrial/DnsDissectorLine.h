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

#ifndef DNSDISSECTORLINE_H
#define DNSDISSECTORLINE_H

#include "DnsTypes.h"

class DnsDissectorLine
{
public:
    DnsDissectorLine();
    ~DnsDissectorLine();

    void Clear();

    static DnsDissectorLine * CreateFromLine(char * line, int linemax);

    int ParseCsvLine(char * line, int linemax);

    const int Number() { 
        return number; 
    };
    const long long Time() {
        return  time;
    };
    const char * Source() {
        return  source;
    };
    const char * Destination() {
        return  destination;
    };
    const char * Protocol() {
        return  protocol;
    };
    const int Length() {
        return  length;
    };
    const bool Is_query() {
        return  is_query;
    };
    const int Query_id() {
        return  query_id;
    };
    const DnsRtype Query_rtype() {
        return  query_rtype;
    };
    const char * Qname() {
        return  qname;
    };
    const int Cname_count() {
        return  cname_count;
    };
    const char * Cname() {
        return  cname;
    };
    const char * A_val() {
        return  a_val;
    };

    static const char * RTypeToText(DnsRtype v);

private:
    int number;
    long long time;
    char * source;
    char * destination;
    char * protocol;
    int length;
    bool is_query;
    int query_id;
    DnsRtype query_rtype;
    char * qname;
    int cname_count;
    char * cname; 
    char * a_val;

    int ParseDnsDissector(char * line, int linemax, int position);
    int ParseQueryType(char * line, int linemax, int position);
    int ParseHexNumber(char * line, int linemax, int position, int * v); 
    static int ParseRType(char * line, int linemax, int position, DnsRtype * v);
    int ParseSpacedString(char * line, int linemax, int position, char ** s);

    static int SkipSpacedString(char * line, int linemax, int position, int * nb_chars);

    static int ParseNumber(char * line, int linemax, int position, int * v);
    static int ParseTime(char * line, int linemax, int position, long long * t);
    static int ParseQuotedString(char * line, int linemax, int position, char ** s);

    static int SkipQuotedString(char * line, int linemax, int position, int * nb_chars);
    static int SkipSpaces(char * line, int linemax, int position);
    static int SkipQuoteAndBlanks(char * line, int linemax, int position);

};

#endif /* DNSDISSECTORLINE_H */
