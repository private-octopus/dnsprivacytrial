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

#ifndef CDNPARSER_H
#define CDNPARSER_H

enum CdnEnum
{
    cdn_null = 0,
    cdn_akamai,
    cdn_cloudflare,
    cdn_disney,
    cdn_fastly,
    cdn_google,
    cdn_amazon,
    cdn_microsoft,
    cdn_facebook,
    cdn_verizon,
    cdn_level3,
    cdn_stackpath,
    cdn_limelight,
    cdn_max
};

typedef struct _cndsuffix
{
    char const * suffix;
    CdnEnum cdn;
} CdnSuffix;

class CdnParser
{
public:
    CdnParser();
    ~CdnParser();

    static CdnEnum FindCdn(char const * cname);
    static char const * GetCdnName(CdnEnum cdn);
private:
    static CdnEnum FindCdnBySuffix(char const * cname);
};


#endif /* CDNPARSER_H */