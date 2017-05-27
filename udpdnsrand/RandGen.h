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
    uint64_t state[2];

    uint64_t xorshift128plus(void);
};

