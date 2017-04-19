#include "DnsTransaction.h"



DnsTransaction::DnsTransaction()
{
}


DnsTransaction::~DnsTransaction()
{
}

int DnsTransaction::Hash()
{
    return 0;
}

bool DnsTransaction::Compare(DnsTransaction * key)
{
    return false;
}

DnsTransaction * DnsTransaction::Merge(DnsTransaction * key)
{
    return nullptr;
}
