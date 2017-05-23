#pragma once
#include <stdint.h>

class RandGen
{
public:
    RandGen();
    ~RandGen();

    void Init(unsigned char * seed, unsigned int seed_length);

    uint32_t GetRandom();

    uint64_t GetRandom64();

    uint32_t GetRandomUniform(uint32_t upper_bound);

    double GetZeroToOne();


private:
    unsigned long long state[2];

    unsigned long long xorshift128plus(void);
};

