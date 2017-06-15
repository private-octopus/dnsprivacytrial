#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <stdint.h>
#include <stdio.h>

typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

class pcap_reader
{
public:
    pcap_reader();
    ~pcap_reader();

    bool is_wrong_endian;
    pcap_hdr_t header;
    pcaprec_hdr_t frame_header;
    uint32_t buffer_size;
    uint8_t * buffer;

    int ip_offset;
    int ip_version;
    int tp_length;
    int tp_offset;
    int tp_version;
    int tp_port1;
    int tp_port2;
    bool is_fragment;
    int fragment_length;

    bool Open(char * f_name, char * f_extract_name);

    bool ReadNext();
    bool WriteExtract();

private:
    FILE * F_pcap;
    FILE * F_extract;

};

#endif /* PCAP_READER_H */
