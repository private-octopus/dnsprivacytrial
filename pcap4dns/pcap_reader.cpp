#include "pcap_reader.h"

pcap_reader::pcap_reader()
    :
    F_pcap(NULL),
    is_wrong_endian(false),
    buffer_size(0),
    buffer (NULL),
    ip_version (0),
    ip_offset(0),
    tp_version(0),
    tp_offset(0),
    tp_length(0),
    tp_port1(0),
    tp_port2(0)
{
}


pcap_reader::~pcap_reader()
{
    if (F_pcap != NULL)
    {
        fclose(F_pcap);
        F_pcap = NULL;
    }

    if (buffer != NULL)
    {
        delete[] buffer;
    }
}

bool pcap_reader::Open(char * f_name)
{
    bool ret = true;

    if (F_pcap != NULL)
    {
        ret = false;
    }
    else
    {
#ifdef WINDOWS
        errno_t err = fopen_s(&F_pcap, f_name, "rb");
#else
        F_pcap = fopen(f_name, "rb");
        int err = (F_pcap == NULL) ? -1 : 0;
#endif

        if (err != 0)
        {
            ret = false;
            printf("Error: %d (0x%x) for %s\n", err, err, f_name);
        }

        if (ret)
        {
            int nb_read = fread(&header, sizeof(header), 1, F_pcap);

            ret = (nb_read == 1);

            if (ret)
            {
                switch (header.magic_number)
                {
                case 0xa1b2c3d4: /* microseconds */
                    break;
                case 0xd4c3b2a1: /* microseconds, swapped */
                    is_wrong_endian = true;
                    break;
                case 0xa1b23c4d: /* nanoseconds */
                    break;
                case 0x4dc3b2a1: /* nanoseconds, swapped */
                    is_wrong_endian = true;
                    break;
                default:
                    ret = false;
                    break;
                }
            }

            if (ret && is_wrong_endian)
            {
                /* TODO: swap the values.. */
            }
        }
    }

    return ret;
}

bool pcap_reader::ReadNext()
{
    int nb_read = fread(&frame_header, sizeof(frame_header), 1, F_pcap);
    bool ret = nb_read == 1;

    ip_version = 0;
    ip_offset = 0;
    tp_version = 0;
    tp_offset = 0;
    tp_length = 0;
    tp_port1 = 0;
    tp_port2 = 0;

    if (ret)
    {

        if (is_wrong_endian)
        {
            /* TODO: swap the values */
        }

        if (frame_header.incl_len > buffer_size)
        {
            int new_size = frame_header.incl_len;
            uint8_t * new_buf = new uint8_t[frame_header.incl_len];
            if (new_buf == NULL)
            {
                ret = false;
            }
            else
            {
                if (buffer != NULL)
                {
                    delete[] buffer;
                }
                buffer = new_buf;
                buffer_size = new_size;
            }
        }

        if (ret)
        {
            int uint8_ts_read = fread(buffer, 1, frame_header.incl_len, F_pcap);
            ret = (uint8_ts_read == frame_header.incl_len);
        }
    }

    if (ret && header.network == 1)
    {
        /* Ethernet */
        int payload_type = (buffer[12] << 8) | (buffer[13]);

        ip_offset = 14;

        switch (payload_type)
        {
        case 0x800:
            /* IPv4 */
            if ((buffer[ip_offset] >> 4) == 4)
            {
                int ip_length = (buffer[ip_offset + 2] << 8) | (buffer[ip_offset + 3]);

                ip_version = 4;

                tp_offset = ip_offset + 20;
                tp_version = buffer[ip_offset + 9];
                tp_length = ip_length - (tp_offset - ip_offset);
            }
            break;
        case 0x86DD:
            /* IPv6, 1 0 0 0 0 1 1 0 1 1 0 1 1 1 0 1 */
            if ((buffer[ip_offset] >> 4) == 6)
            {
                ip_version = 6;

                tp_offset = ip_offset + 40;
                tp_version = buffer[ip_offset + 6];
                tp_length = (buffer[ip_offset + 4] << 8) | (buffer[ip_offset + 5]);
            }
            break;
        default:
            break;
        }

        if (tp_length != 0)
        {
            tp_port1 = (buffer[tp_offset] << 8) | (buffer[tp_offset + 1]);
            tp_port2 = (buffer[tp_offset + 2] << 8) | (buffer[tp_offset + 3]);
        }
    }

    return ret;
}