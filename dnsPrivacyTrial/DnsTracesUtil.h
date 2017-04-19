#pragma once

/*
template <typename TUINT, UINT CODELENGTH = sizeof(TUINT)>
void TlsEncodeInt(TUINT x, _Out_writes_(CODELENGTH) BYTE* message)
{
    TUINT r = x;

    for (UINT i = CODELENGTH; i > 0;)
    {
        i--;
        message[i] = (BYTE)(r & 255);
        r >>= 8;
    }
}

template<>
void TlsEncodeInt<BYTE>(BYTE x, _Out_writes_(1) BYTE* message);
*/

template <typename OBJTYPE>
bool CheckArrayAllocation(int n, int * allocated, int nbStored, OBJTYPE*** storedArray)
{
    bool ret = true;

    if (*allocated < n)
    {
        int na = (*allocated == 0) ? 128 : *allocated;

        while (na < n)
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
        for (int i = 0; i < v_size; v++)
        {
            delete v[i];
            v[i] = NULL;
        }

        delete[] v;

    }
}

template <typename OBJTYPE>
class THashTable
{
private:
    int table_size;
    int index_count;
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

            int hash_bucket = hash%table_size;

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

private:
    bool ResizeTable() {
        bool ret = true;
        int new_size = 0;
        int new_count = index_count + 1;
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
                        }
                    }

                    delete[] old_table;
                }
            }
        }

        return ret;
    }

    OBJTYPE * DoInsertOrMerge(OBJTYPE * key) {
        int hash_bucket = key->Hash()%table_size;
        OBJTYPE * ret = NULL;

        for (int i = 0; ret == false && i < table_size; i++)
        {
            if (hash_table[hash_bucket] == NULL)
            {
                hash_table[hash_bucket] = key;
                ret = key;
            }
            else if (hash_table[hash_bucket].Compare(key))
            {
                ret = hash_table[hash_bucket].Merge(key);
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

