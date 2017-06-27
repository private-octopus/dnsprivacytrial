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

#ifndef DNSTRACESUTIL_H
#define DNSTRACESUTIL_H

#include <string.h>

template <typename OBJTYPE>
bool CheckArrayAllocation(int n, int * allocated, int nbStored, 
    OBJTYPE*** storedArray)
{
    bool ret = true;

    if (*storedArray == NULL && nbStored > 0)
    {
        ret = false;
    }
    else if (nbStored > *allocated)
    {
        ret = false;
    }
    else if (*allocated <= n || *storedArray == NULL)
    {
        int na = (*allocated == 0) ? 128 : *allocated;

        while (na <= n || na < nbStored)
        {
            na = 2 * na;
        }

        OBJTYPE ** newSet = new OBJTYPE*[na];

        if (newSet == NULL)
        {
            ret = false;
        }
        else
        {
            for (int i = 0; i < nbStored; i++)
            {
                newSet[i] = (*storedArray)[i];
                (*storedArray)[i] = NULL;
            }

            for (int i = nbStored; i < na; i++)
            {
                newSet[i] = NULL;
            }

            if (*storedArray != NULL)
            {
                delete[] * storedArray;
            }

            *storedArray = newSet;
            *allocated = na;
        }
    }

    return ret;
}

template <typename OBJTYPE>
void TArrayDelete(OBJTYPE** v, int v_size) {
    if (v != NULL)
    {
        for (int i = 0; i < v_size; i++)
        {
            if (v[i] != NULL)
            {
                delete v[i];
                v[i] = NULL;
            }
        }

        delete[] v;

    }
}

template <typename OBJTYPE>
class THashTable
{
private:
    unsigned int table_size;
    unsigned int index_count;
    OBJTYPE ** hash_table;

public:
    THashTable()
        :
        table_size(0),
        index_count(0),
        hash_table(NULL)
    {}

    ~THashTable() {
        if (hash_table != NULL)
        {
            TArrayDelete<OBJTYPE>(hash_table, table_size);
        }
    }

    OBJTYPE * Retrieve(OBJTYPE * key) {
        OBJTYPE * ret = NULL;

        if (hash_table != NULL)
        {
            unsigned int hash = key->Hash();

            unsigned int hash_bucket = hash%table_size;

            for (int i = 0; ret == false && i < table_size; i++)
            {
                if (hash_table[hash_bucket] == NULL)
                {
                    /* no such entry! */
                    break;
                }
                else if (hash_table[hash_bucket].CompareKey(key))
                {
                    ret = hash_table[hash_bucket];
                    break;
                }
                else
                {
                    hash_bucket++;
                    if (hash_bucket >= table_size)
                    {
                        hash_bucket = 0;
                    }
                }
            }
        }

        return ret;
    }

    OBJTYPE * InsertOrMerge(OBJTYPE * key)
    {
        OBJTYPE * ret = NULL;

        if (ResizeTable())
        {
            ret = DoInsertOrMerge(key);
        }

        return ret;
    }

    const OBJTYPE ** HashTable() { 
        return (const OBJTYPE **) hash_table;
    };

    const unsigned int TableSize() {
        return (const unsigned int) table_size;
    };

private:
    bool ResizeTable() {
        bool ret = true;
        unsigned int new_size = 0;
        unsigned int new_count = index_count + 1;
        OBJTYPE ** new_table;

        if (new_count * 2 > table_size)
        {
            if (table_size == 0)
            {
                new_size = 128;
            }
            else
            {
                new_size = 2 * table_size;
            }

            while (new_count * 8 > new_size)
            {
                new_size *= 2;
            }

            new_table = new OBJTYPE*[new_size];

            if (new_table == 0)
            {
                ret = false;
            }
            else
            {
                OBJTYPE ** old_table = hash_table;
                int old_count = index_count;

                memset(new_table, 0, sizeof(OBJTYPE*)*new_size);

                hash_table = new_table;
                table_size = new_size;
                index_count = 0;
                if (old_table != NULL)
                {
                    for (int i = 0; i < old_count; i++)
                    {
                        if (old_table[i] != NULL)
                        {
                            if (DoInsertOrMerge(old_table[i]) == NULL)
                            {
                                ret = false;
                            }
                            
                            old_table[i] = NULL;
                        }
                    }

                    delete[] old_table;
                }
            }
        }

        return ret;
    }

    OBJTYPE * DoInsertOrMerge(OBJTYPE * key) {
        unsigned int hash_bucket = key->Hash()%table_size;
        OBJTYPE * ret = NULL;

        for (unsigned int i = 0; ret == false && i < table_size; i++)
        {
            if (hash_table[hash_bucket] == NULL)
            {
                hash_table[hash_bucket] = key;
                index_count++;
                ret = key;
            }
            else if (hash_table[hash_bucket]->Compare(key))
            {
                hash_table[hash_bucket]->Merge(key);
                ret = hash_table[hash_bucket];
                break;
            }
            else
            {
                hash_bucket++;
                if (hash_bucket >= table_size)
                {
                    hash_bucket = 0;
                }
            }
        }

        return ret;
    }
};

char * CopyString(const char * s);

unsigned int BasicHash(unsigned int h, const unsigned char * x, unsigned int l);

unsigned int BasicHash(unsigned int h, int x);

unsigned int BasicHash(unsigned int h, const char * s);

#endif /* DNSTRACESUTIL_H */
