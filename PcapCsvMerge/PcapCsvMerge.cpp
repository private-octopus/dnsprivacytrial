// PcapCsvMerge.cpp : Defines the entry point for the console application.
//

#include "PcapCsvReader.h"

char * GetFileName(char * x)
{
    char* fname = x;

    while (*x)
    {
        if (*x == '/' || *x == '\\')
        {
            fname = x + 1;
        }
        x++;
    }

    return(fname);
}


int main(int argc, char ** argv)
{
    bool ret = true;
    int nb_readers = argc - 1;
    PcapCsvReader * reader = NULL;
    pcap_csv_line current_line;

    if (nb_readers <= 0)
    {
        fprintf(stderr, "Usage: %s <f1.csv> ... <fn.csv> > output.csv\n", argv[0]);
        ret = false;
    }
    else
    {
        reader = new PcapCsvReader[nb_readers];
        if (reader == NULL)
        {
            fprintf(stderr, "Cannot allocate %d readers.\n", nb_readers);
            ret = false;
        }
    }

    if (ret)
    {
        for (int i = 0; ret && (i < nb_readers); i++)
        {
            ret = reader[i].Open(argv[i + 1]);

            if (!ret)
            {
                fprintf(stderr, "Cannot open reader for <%s>.\n", argv[i + 1]);
            }
        }
    }

    if (ret)
    {
        printf("R-ID, R-Name, K-Type, Key, Key name,");

        for (int i = 0; i < nb_readers; i++)
        {
            printf("F-%d,", i + 1);
        }
        printf("\n");

        for (int i = 0; i < nb_readers; i++)
        {
            printf("0, Input File, 1, %s, F-%d,", GetFileName(argv[i+1]), i+1);
            for (int j = 0; j < nb_readers; j++)
            {
                if (j == i)
                {
                    printf("1,");
                }
                else
                {
                    printf(",");
                }
            }
            printf("\n");
        }
    }

    while (ret)
    {
        bool at_least_one = false;

        for (int i = 0; ret && i < nb_readers; i++)
        {
            if (!reader[i].is_finished)
            {
                if (!at_least_one)
                {
                    at_least_one = true;
                    current_line = reader[i].line;
                }
                else
                {
                    if (reader[i].IsLower(&current_line))
                    {
                        current_line = reader[i].line;
                    }
                }
            }
        }

        if (!at_least_one)
        {
            break;
        }
        else
        {
            // Print the header of the current line
            printf("%d, ""%s"", ", current_line.registry_id, current_line.registry_name);

            printf("%d,", current_line.key_type);
            if (current_line.key_type == 0)
            {
                printf("%d,", current_line.key_number);
            }
            else
            {
                printf("""%s"",", current_line.key_value);
            }

            printf("""%s"",", current_line.key_name);

            // Print the count for each line present
            for (int i = 0; ret && i < nb_readers; i++)
            {
                if (!reader[i].is_finished &&
                    reader[i].IsEqual(&current_line))
                {
                    printf("%d,", reader[i].line.count);
                    reader[i].ReadNext();
                }
                else
                {
                    printf("0,");
                }
            }
            // And finish the csv line...
            printf("\n");
        }
    }

    return 0;
}

