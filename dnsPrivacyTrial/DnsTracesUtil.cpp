#include <stdlib.h>
#include <string.h>
#include "DnsTracesUtil.h"

char * CopyString(const char * s)
{
    char * x = NULL;

    if (s != NULL)
    {
        size_t l = strlen(s);
        x = new char[l + 1];

        if (x != NULL)
        {
            errno_t er = memcpy_s(x, l + 1, s, l);
            if (er != 0)
            {
                free(x);
                x = NULL;
            }
            else
            {
                x[l] = 0;
            }
        }
    }

    return x;
}

unsigned int BasicHash(unsigned int h, const unsigned char * x, unsigned int l)
{
    for (unsigned int i = 0; i < l; i++)
    {
        unsigned int r = h >> 24;
        h <<= 8;
        h |= x[i];
        h ^= ((r << 16) | r);
    }

    return h;
}

unsigned int BasicHash(unsigned int h, int x) {
    return BasicHash(h, (const unsigned char *)&x, sizeof(int));
}

unsigned int BasicHash(unsigned int h, const char * s) {
    return (s == NULL) ? h : BasicHash(h, (const unsigned char *)s, strlen(s));
}