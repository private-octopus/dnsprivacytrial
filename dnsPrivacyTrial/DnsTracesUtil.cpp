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
#ifdef WINDOWS
            errno_t er = memcpy_s(x, l + 1, s, l);
            if (er != 0)
            {
                delete[] x;
                x = NULL;
            }
            else
            {
                x[l] = 0;
            }
#else
            memcpy(x, s, l);
            x[l] = 0;
#endif
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
    return (s == NULL) ? h : BasicHash(h, (const unsigned char *)s, (unsigned int) strlen(s));
}