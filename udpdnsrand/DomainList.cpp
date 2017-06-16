#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "DomainList.h"

DomainList::DomainList()
{
}


DomainList::~DomainList()
{
}

bool DomainList::Init(char * namelist, int nb_names)
{
    FILE * F;
    int nb_names_added = 0;
#ifdef WINDOWS
    errno_t er = fopen_s(&F, namelist, "r");
    bool ret = er == 0;
#else
    bool ret;
    F = fopen(namelist,"r");
    ret = (F != NULL);
#endif
    if (ret)
    {
        char name_line[1024];
        DomainNameObject dom;

        while (fgets(name_line, 1024, F))
        {
            bool got_comma = false;
            bool got_alpha = false;
            bool got_dot = false;
            bool got_zero = false;
            int start = 0;
            for (; start < sizeof(name_line); start++)
            {
                char x = name_line[start];
                if (x == ',')
                {
                    got_comma = true;
                    start++;
                    break;
                }
                else if (x == 0)
                {
                    break;
                }
            }

            if (got_comma)
            {
                for (int i = 0; i < sizeof(dom.DomainName); i++)
                {
                    char x = name_line[start + i];
                    if (x == 0 || x <= ' ' || x >= 127 || x == ',')
                    {
                        dom.DomainName[i] = 0;
                        got_zero = true;
                        break;
                    }
                    else
                    {
                        if (x == '.')
                        {
                            got_dot = true;
                        }
                        else if (x >= 'a' && x <= 'z')
                        {
                            got_alpha = true;
                        }
                        else if (x >= 'A' && x <= 'Z')
                        {
                            got_alpha = true;
                            x -= ('A' - 'a');
                        }
                        dom.DomainName[i] = x;
                    }
                }
            }

            if (got_comma && got_zero && got_dot && got_alpha)
            {
                dictionary.InsertOrAdd(&dom);
                nb_names_added++;

                if (nb_names != 0 && nb_names_added >= nb_names)
                {
                    break;
                }
            }
        }

        fclose(F);
    }
    return ret;
}

char const * DomainList::GetRandomDomain() 
{
    char * s = NULL;
    uint32_t hash = r.GetRandom();
    DomainNameObject * x = dictionary.GetClosest(hash);

    if (x != NULL)
    {
        s = x->DomainName;
    }

    return s;
}


uint32_t DomainNameObject::Hash()
{
    uint32_t x = 0;

    for (int i = 0; DomainName[i] != 0; i++)
    {
        x ^= (x >> 17) ^ (x << 13) ^ DomainName[i];
    }
    return x;
}

DomainNameObject * DomainNameObject::CreateCopy()
{
    DomainNameObject * x = new DomainNameObject();
    if (x != NULL)
    {
#ifdef WINDOWS
        (void) strcpy_s(x->DomainName, DomainName);
#else
        strcpy(x->DomainName, DomainName);
#endif
    }
    return x;
}

bool DomainNameObject::IsSameKey(DomainNameObject * key)
{
    return strcmp(key->DomainName, DomainName);
}

void DomainNameObject::Add(DomainNameObject * key)
{
    /* Do nothing */
}
