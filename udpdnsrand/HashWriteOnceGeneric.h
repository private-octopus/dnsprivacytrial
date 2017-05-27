#pragma once
#include <stdint.h>
#include <stdlib.h>

template <class KeyObj>
class HashWriteOnce
{
public:
    HashWriteOnce()
        :
        tableSize(0),
        tableCount(0),
        hashTable(NULL)
    {}

    ~HashWriteOnce()
    {
        Clear();
    }

    bool InsertOrAdd(KeyObj * key, bool need_alloc = true)
    {
        bool ret = true;
        unsigned int newCount = tableCount + 1;

        if (key == 0)
        {
            ret = false;
        }
        else if (tableSize < 2 * newCount)
        {
            unsigned int newSize = tableSize;

            if (tableSize == 0)
            {
                newSize = 128;
            }

            while (newSize < 4 * newCount)
            {
                newSize *= 2;
            }

            ret = Resize(newSize);
        }

        if (ret)
        {
            ret = DoInsert(key, need_alloc);
        }

        return ret;
    }

    uint32_t GetCount() {
        return tableCount;
    }

    uint32_t GetSize() {
        return tableSize;
    }

    KeyObj * GetEntry(uint32_t indx)
    {
        return (indx < tableSize) ? hashTable[indx] : NULL;
    }

    KeyObj * GetClosest(uint32_t hash)
    {
        uint32_t hash_index = hash%tableSize;
        KeyObj * x = NULL;

        for (uint32_t i = 0; i < tableSize; i++)
        {
            x = hashTable[hash_index];
            if (x != NULL)
            {
                break;
            }
            else
            {
                hash_index++;

                if (hash_index >= tableSize)
                {
                    hash_index = 0;
                }
            }
        }

        return x;
    }

private:
    uint32_t tableSize;
    uint32_t tableCount;
    KeyObj ** hashTable;

    void Clear()
    {
        if (hashTable != NULL)
        {
            for (uint32_t i = 0; i < tableSize; i++)
            {
                if (hashTable[i] != NULL)
                {
                    delete hashTable[i];
                    hashTable[i] = NULL;
                }
            }

            delete[] hashTable;
            hashTable = NULL;
        }

        tableCount = 0;
        tableSize = 0;
    }

    bool Resize(unsigned newSize)
    {
        bool ret = false;
        KeyObj ** oldTable = hashTable;
        uint32_t oldSize = tableSize;

        if (oldSize >= newSize)
        {
            ret = true;
        }
        else
        {
            KeyObj ** newTable = new KeyObj*[newSize];

            if (newTable != NULL)
            {
                hashTable = newTable;
                tableSize = newSize;
                memset(hashTable, 0, sizeof(KeyObj *)*tableSize);
                ret = true;
                tableCount = 0;

                if (oldTable != NULL)
                {
                    for (unsigned int i = 0; ret && i < oldSize; i++)
                    {
                        if (oldTable[i] != NULL)
                        {
                            ret = DoInsert(oldTable[i], false);
                            oldTable[i] = NULL;
                        }
                    }

                    if (!ret)
                    {
                        hashTable = oldTable;
                        tableSize = oldSize;
                        delete[] newTable;
                    }
                    else
                    {
                        delete[] oldTable;
                    }
                }
            }
        }
        return ret;
    }

    bool DoInsert(KeyObj * key, bool need_alloc)
    {
        bool ret = false;
        uint32_t hash_index = key->Hash()%tableSize;

        for (uint32_t i = 0; i < tableSize; i++)
        {
            if (hashTable[hash_index] == NULL)
            {
                if (need_alloc)
                {
                    hashTable[hash_index] = key->CreateCopy();
                    if (hashTable[hash_index] != NULL)
                    {
                        tableCount++;
                        ret = true;
                    }
                    else
                    {
                        ret = false;
                    }
                }
                else
                {
                    hashTable[hash_index] = key;
                    tableCount++;
                    ret = true;
                }
                break;
            }
            else if (key->IsSameKey(hashTable[hash_index]))
            {
                /* found it. Just increment the counter */
                hashTable[hash_index]->Add(key);
                ret = false;
                break;
            }
            else
            {
                hash_index++;

                if (hash_index >= tableSize)
                {
                    hash_index = 0;
                }
            }
        }

        return ret;
    }
};
