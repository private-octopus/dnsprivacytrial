#pragma once

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

