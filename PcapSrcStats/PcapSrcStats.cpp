// PcapSrcStats.cpp : Defines the entry point for the console application.
//
#include <string.h>
#include "../pcap4dns/pcap_reader.h"
#include "../udpdnsrand/HashWriteOnceGeneric.h"

class AddressContainer
{
public:
    AddressContainer() 
        :
        hash(0),
        count(0),
        address_type(0)
    {};
    ~AddressContainer() {};

    uint32_t Hash()
    {
        if (hash == 0)
        {
            uint32_t l = (address_type == 4) ? 4 : 16;

            hash = l;

            for (uint32_t i = 0; i < l; i++)
            {
                hash ^= (hash >> 17) ^ (hash << 13) ^ address[i];
            }
        }

        return hash;
    };

    bool IsSameKey(AddressContainer * key)
    {
        bool ret = address_type == key->address_type;

        if (ret)
        {
            uint32_t l = (address_type == 4) ? 4 : 16;
            ret = memcmp(address, key->address, l) == 0;
        }

        return ret;
    };

    void Add(AddressContainer * key)
    {
        count += key->count;
    };

    AddressContainer * CreateCopy()
    {
        AddressContainer * ret = new AddressContainer();
        if (ret != 0)
        {
            ret->hash = hash;
            ret->count = count;
            ret->address_type = address_type;
            memcpy(ret->address, address, sizeof(address));
        }

        return ret;
    };

    void SetAddress(uint32_t address_type, uint8_t * address)
    {
        hash = 0;
        count = 1;
        this->address_type = address_type;

        if (address_type == 4)
        {
            (void) memcpy(this->address, address, 4);
            (void)memset(this->address + 4, 0, 12);
        }
        else
        {
            (void)memcpy(this->address, address, 16);
        }
    }

    uint32_t hash;
    uint32_t count;
    uint32_t address_type;
    uint8_t address[16];
};

bool ExportResults(char * fileName, 
    HashWriteOnce<AddressContainer> * source_table,
    HashWriteOnce<AddressContainer> * good_table,
    uint32_t * nb_results)
{
    FILE* F;
    AddressContainer *source_key;
    AddressContainer *good_key;

#ifdef WINDOWS
    errno_t err = fopen_s(&F, fileName, "w");
    bool ret = (err == 0);
#else
    bool ret;

    F = fopen(fileName, "w");
    ret = (F != NULL);
#endif

    * nb_results = 0;

    if (ret)
    {
        for (uint32_t i = 0; i < source_table->GetSize(); i++)
        {
            source_key = source_table->GetEntry(i);
            if (source_key != NULL)
            {
                uint32_t good_count = 0;
                good_key = good_table->Retrieve(source_key);
                if (good_key != NULL)
                {
                    good_count = good_key->count;
                }

                if (source_key->address_type == 4)
                {
                    fprintf(F, "%d.%d.%d.%d,",
                        source_key->address[0], source_key->address[1],
                        source_key->address[2], source_key->address[3]);
                }
                else
                {
                    for (int i = 0; i < 8; i++)
                    {
                        uint32_t x = (source_key->address[2 * i] << 8) + source_key->address[(2 * i) + 1];
                        fprintf(F, "%x%c", x, (i < 7) ? ':' : ',');
                    }
                }
                fprintf(F, "%d, %d,\n", source_key->count, good_count);
                *nb_results += 1;
            }
        }

        fclose(F);
    }
    return ret;
}

int main(int argc, char ** argv)
{
    pcap_reader reader;
    pcap_reader extract;
    uint32_t nb_records_read = 0;
    uint32_t nb_extracts_read = 0;
    uint32_t nb_results = 0;
    char * extract_file = (char *) "smalltest.pcap";
    char * input_file = (char *) "smalltest.pcap";
    char * result_file = (char *) "addressList.csv";
    HashWriteOnce<AddressContainer> source_table;
    HashWriteOnce<AddressContainer> good_table;
    bool no_problem = true;

    if (argc > 1)
    {
        input_file = argv[1];

        if (argc > 2)
        {
            extract_file = argv[2];

            if (argc > 3)
            {
                result_file = argv[3];
            }
        }
    }

    /* Read extract file, place addresses in source table */

    if (!extract.Open(extract_file, NULL))
    {
        no_problem = false;
        printf("Could not open extract file <%s>.\n", extract_file);
    }
    else
    {
        AddressContainer skey, dkey;

        while (extract.ReadNext())
        {
            /* Check that this is a DNS packet, to remove noise */
            if (!(extract.tp_version == 17 &&
                (extract.tp_port1 == 53 || extract.tp_port2 == 53)))
            {
                continue;
            }
            
            /* now, check whether the source and dest IP are in the extract */
            if (extract.ip_version == 4)
            {
                /* Store the source and dest IPv4 address */
                skey.SetAddress(extract.ip_version, &extract.buffer[extract.ip_offset + 12]);
                dkey.SetAddress(extract.ip_version, &extract.buffer[extract.ip_offset + 16]);
            }
            else if (extract.ip_version == 6)
            {
                /* Store the source and dest IPv6 address */
                skey.SetAddress(extract.ip_version, &extract.buffer[extract.ip_offset + 8]);
                dkey.SetAddress(extract.ip_version, &extract.buffer[extract.ip_offset + 24]);
            }
            else
            {
                continue;
            }
            nb_extracts_read++;

            /* Store the source and dest addresses */
            (void) source_table.InsertOrAdd(&skey, true);
            (void) source_table.InsertOrAdd(&dkey, true);
        }
        
        printf("Retrieved %d records from %s, obtained %d addresses.\n",
                nb_extracts_read, extract_file, source_table.GetCount());
    }

    if (no_problem)
    {
        if (!reader.Open(input_file, NULL))
        {
            no_problem = false;
            printf("Could not open input file <%s>.\n", input_file);
        }
    }

    if (no_problem)
    {
        AddressContainer skey, dkey;

        while (reader.ReadNext())
        {
            bool is_good_dns_response = false;

            /* Check that this is ipv4 or ipv6 */
            if (reader.ip_version != 4 && reader.ip_version != 6)
            {
                continue;
            }

            nb_records_read++;

            /* Check that this is a DNS response and that the return code is OK */
            if (reader.tp_version == 17 &&
                (reader.tp_port1 == 53 || reader.tp_port2 == 53))
            {
                uint8_t * dnsqr = reader.buffer + reader.tp_offset + 8;

                if ((dnsqr[3] & 0x80) != 0 &&
                    (dnsqr[4] & 0x0F) == 0)
                {
                    is_good_dns_response = true;
                }
            }

            if (!is_good_dns_response)
            {
                continue;
            }
            
            /* now, check whether the source and dest IP are in the extract */
            if (reader.ip_version == 4)
            {
                /* Store the source and dest IPv4 address */
                skey.SetAddress(reader.ip_version, &reader.buffer[reader.ip_offset + 12]);
                dkey.SetAddress(reader.ip_version, &reader.buffer[reader.ip_offset + 16]);
            }
            else /* we checked that the address type is 4 or 6 already */
            {
                /* Store the source and dest IPv6 address */
                skey.SetAddress(reader.ip_version, &reader.buffer[extract.ip_offset + 8]);
                dkey.SetAddress(reader.ip_version, &reader.buffer[extract.ip_offset + 24]);
            }

            if (source_table.Retrieve(&skey) != NULL &&
                source_table.Retrieve(&dkey) != NULL)
            {
                /* Both addresses are in the extract file */
                good_table.InsertOrAdd(&skey, true);
                good_table.InsertOrAdd(&dkey, true);
            }
        }
        
        printf("Retrieved %d records from %s, obtained %d addresses.\n",
            nb_records_read, input_file, good_table.GetCount());
    }

    /* Write the report by going through the source table, and putting the result in CSV file */
    if (no_problem)
    {
        if (ExportResults(result_file, &source_table, &good_table, &nb_results))
        {
            printf("Wrote %d results on file %s\n", nb_results, result_file);
        }
        else
        {
            printf("Could not open result file <%s>\n", result_file);
        }
    }

    return 0;
}

