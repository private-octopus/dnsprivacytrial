// pcap4dns.cpp : Defines the entry point for the console application.
//

#ifdef WINDOWS
#include "stdafx.h"
#else
#include "stdio.h"
#endif

#include "pcap_reader.h"
#include "DnsStats.h"


int main(int argc, char ** argv)
{
    pcap_reader reader;
    int nb_records_read = 0;
    bool found_v4 = false;
    bool found_v6 = false;
    DnsStats stats;
    int nb_udp_dns = 0;
    char * inputFile = (char *) "smalltest.pcap";
    char * csv_file = (char *) "smalltest.csv";

    if (argc > 1)
    {
        inputFile = argv[1];

        if (argc > 2)
        {
            csv_file = argv[2];
        }
    }

    if (reader.Open(inputFile))
    {
        printf("Open succeeds, magic = %x, v =  %d/%d, lmax = %d, net = %x\n",
            reader.header.magic_number,
            reader.header.version_major,
            reader.header.version_minor,
            reader.header.snaplen,
            reader.header.network
        );

        while (reader.ReadNext())
        {
            nb_records_read++;
            if (nb_records_read <= 10 ||
                (reader.ip_version == 4 && !found_v4) ||
                (reader.ip_version == 6 && !found_v6))
            {
                printf("Record %d, l = %d, ip: %d, tp: %d, tp_l: %d, %d:%d\n",
                    nb_records_read, reader.frame_header.incl_len,
                    reader.ip_version, reader.tp_version, reader.tp_length,
                    reader.tp_port1, reader.tp_port2);
                found_v4 |= (reader.ip_version == 4);
                found_v6 |= (reader.ip_version == 6);
            }

            if (reader.tp_version == 17 &&
                (reader.tp_port1 == 53 || reader.tp_port2 == 53))
            {
                stats.SubmitPacket(reader.buffer + reader.tp_offset + 8,
                    reader.tp_length - 8);
                nb_udp_dns++;
            }
        }

        printf("Read %d records, %d dns records.\n", nb_records_read, nb_udp_dns);

        if (stats.ExportToCsv(csv_file))
        {
            printf("Exported results to %s\n", csv_file);
        }
        else
        {
            printf("Could not write to %s\n", csv_file);
        }
    }
    return 0;
}

