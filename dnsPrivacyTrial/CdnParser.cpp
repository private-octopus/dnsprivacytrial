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

#include "CdnParser.h"

static CdnSuffix cdn_suffixes[] = {
    { "a-msedge.net", cdn_microsoft },
    { "akadns.net", cdn_akamai },
    { "akadns6.net", cdn_akamai },
    { "akamai.net", cdn_akamai },
    { "akamaiedge.net", cdn_akamai },
    { "amazonaws.com", cdn_amazon },
    { "aol.com", cdn_verizon },
    { "azurewebsites.net", cdn_microsoft },
    { "c-msedge.net", cdn_microsoft },
    { "cloudapp.net", cdn_microsoft },
    { "cloudflare.net", cdn_cloudflare },
    { "cloudfront.net", cdn_amazon },
    { "disneyprivacycenter.com", cdn_disney },
    { "disneytermsofuse.com", cdn_disney },
    { "doubleclick.net", cdn_google },
    { "e-msedge.net", cdn_microsoft },
    { "edgecastcdn.net", cdn_verizon },
    { "elasticbeanstalk.com", cdn_amazon },
    { "epsiloncdn.net", cdn_verizon },
    { "facebook.com", cdn_facebook },
    { "fastly.net", cdn_fastly },
    { "fastlylb.net", cdn_fastly },
    { "fbcdn.net", cdn_facebook },
    { "footprint.net", cdn_level3 },
    { "go.com", cdn_disney },
    { "google.com", cdn_google },
    { "googlehosted.com", cdn_google },
    { "instagram.com", cdn_facebook },
    { "itmdb.net", cdn_level3 },
    { "linkedin.com", cdn_microsoft },
    { "llnwd.net", cdn_limelight },
    { "microsoft.com", cdn_microsoft },
    { "netdna-cdn.com", cdn_stackpath },
    { "nsatc.net", cdn_level3 },
    { "s-msedge.net", cdn_microsoft },
    { "v0cdn.net", cdn_verizon },
    { "v2cdn.net", cdn_verizon },
    { "yahoo.com", cdn_verizon },
    { "yahoodns.net", cdn_verizon }
};

static int nb_cdn_suffixes = (int) sizeof(cdn_suffixes) / sizeof(CdnSuffix);

static const char * cdn_name[] = {
    "",
    "Akamai",
    "Cloudflare",
    "Disney",
    "Fastly",
    "Google",
    "Amazon",
    "Microsoft",
    "Facebook",
    "Verizon",
    "Level3",
    "Stackpath",
    "Limelight",
    ""
};

CdnParser::CdnParser()
{
}


CdnParser::~CdnParser()
{
}

CdnEnum CdnParser::FindCdn(char const * cname)
{
    int indx = 0;
    CdnEnum ret = cdn_null;

    do {
        ret = FindCdnBySuffix(&cname[indx]);

        if (ret != cdn_null)
        {
            break;
        }
        else
        {
            while (cname[indx] != 0)
            {
                if (cname[indx] == '.')
                {
                    indx++;
                    break;
                }
                else
                {
                    indx++;
                }
            }
        }
    } while (cname[indx] != 0);

    return ret;
}


char const * CdnParser::GetCdnName(CdnEnum cdn)
{
    return cdn_name[cdn];
}

/*
 * search algorithm assumes that suffixes are sorted alphabetically
 */
CdnEnum CdnParser::FindCdnBySuffix(char const * lower_case_suffix)
{
    int low = -1;
    int high = nb_cdn_suffixes;
    int x = (high + low) / 2;
    bool is_valid = false;
    int cmp;
    CdnEnum ret = cdn_null;

    for (;;)
    {
        /* compare tld & valid_tld[x] */
        int i = 0;
        cmp = 0;

        for (i = 0; lower_case_suffix[i] != 0; i++)
        {
            if (cdn_suffixes[x].suffix[i] == 0)
            {
                cmp = 1;
                break;
            }
            else if (cdn_suffixes[x].suffix[i] > lower_case_suffix[i])
            {
                cmp = -1;
                break;
            }
            else if (cdn_suffixes[x].suffix[i] < lower_case_suffix[i])
            {
                cmp = 1;
                break;
            }
        }

        if (cmp == 0 && cdn_suffixes[x].suffix[i] != 0)
        {
            cmp = -1;
        }

        if (cmp == 0)
        {
            ret = cdn_suffixes[x].cdn;
            break;
        }
        else if (cmp < 0)
        {
            high = x;
        }
        else
        {
            low = x;
        }

        x = (low + high) / 2;

        if (x <= low || x >= high)
        {
            break;
        }
    }

    return ret;
}
