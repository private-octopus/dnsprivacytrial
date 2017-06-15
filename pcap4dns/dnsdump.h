#ifndef DNSDUMP_H
#define DNSDUMP_H

#include <stdint.h>
#include <stdio.h>

class dnsdump
{
public:
    dnsdump();
    ~dnsdump();

    int dns_name_dump(uint8_t * response, int response_length, int start);
    char * rr_type_string(int rr_type, char * buffer);

    int query_dump(uint8_t* response, int response_length, int start);
    int record_dump(uint8_t* response, int response_length, int start);
    void dns_dump(uint8_t* response, int response_length);

    /* void dnsdump::message_dump(SOCKADDR* addr_from, uint8_t* response, int response_length); */

};

#endif /* DNSDUMP_H */