#ifndef PCAPCSVREADER_H
#define PCAPCSVREADER_H

#include <stdio.h>

typedef struct _pcap_csv_line
{
    int registry_id;
    char registry_name[64];
    int key_type;
    union
    {
        int key_number;
        char key_value[64];
    };
    char key_name[64];
    int count;
} pcap_csv_line;


class PcapCsvReader
{
public:
    PcapCsvReader();
    ~PcapCsvReader();

    bool Open(char * filekey_name);

    void ReadNext();

    bool IsLower(pcap_csv_line * low_line);

    bool IsEqual(pcap_csv_line * low_line);

    pcap_csv_line line;
    FILE * F;
    bool is_finished;
    char buffer[512];

private:
    int read_number(int* number, int start);
    int read_string(char* text, int text_max, int start);
};

#endif