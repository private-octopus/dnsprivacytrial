#pragma once
#include <stdint.h>
#include "HashWriteOnceGeneric.h"
#include "RandGen.h"

struct DomainNameObject
{
    char DomainName[256];

    uint32_t Hash();
    DomainNameObject* CreateCopy();
    bool IsSameKey(DomainNameObject* key);
    void Add(DomainNameObject* key);
};

class DomainList
{
public:
    DomainList();
    ~DomainList();

    bool Init(char * namelist, int nb_names); /* init generation with list of names */

    char const * GetRandomDomain();

    // bool SubmitNewName(char * domainName);

private:
    HashWriteOnce<DomainNameObject> dictionary;
    RandGen r;
};

