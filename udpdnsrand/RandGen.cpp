#include "RandGen.h"

/* Initialize state set to the first digits of PI */

static const uint64_t initialState[2] = {
    0x243F6A8885A308D3ULL,
    0x13198A2E03707344ULL
};

RandGen::RandGen()
{   
    state[0] = initialState[0];
    state[1] = initialState[1];
}


RandGen::~RandGen()
{
}

void RandGen::Init(unsigned char * seed, unsigned int seed_length)
{
    uint8_t * us = (uint8_t *)state;
    const uint8_t * s0 = (const uint8_t *) initialState ;
    uint32_t x_seed = 0;

    for (uint32_t i = 0; i < sizeof(state); i++)
    {
        us[i] = s0[i] ^ seed[x_seed];
        x_seed++;
        if (x_seed >= seed_length)
            x_seed = 0;
    }
}

uint32_t RandGen::GetRandom()
{
    return (uint32_t)(xorshift128plus() & 0xFFFFFFFF);
}

uint64_t RandGen::GetRandom64()
{
    return xorshift128plus();
}

uint32_t RandGen::GetRandomUniform(uint32_t upper_bound)
{
    uint64_t r, min;

    if (upper_bound < 2)
        return 0;

    /* 2**64 % x == (2**64 - x) % x */
    min = ((uint64_t)(-(int64_t)upper_bound)) % upper_bound;

    /*
    * This could theoretically loop forever but each retry has
    * only at most 1 in 2^32 chance of selecting a number
    * inside the minimum, so there is hardly any chance to re-roll.
    */
    for (;;) {
        r = GetRandom64();
        if (r >= min)
            break;
    }

    return (uint32_t)(r % upper_bound);
}

double RandGen::GetZeroToOne()
{
    /* Keep 53 random bits, same as mantissa of IEEE 754 double */
    uint64_t r = GetRandom64();
    double d = (double)(r & 0xFFFFFFFFFFFFF);
    d /= (double)(0x10000000000000ull);
    return d;
}

/*
 * The xorshift128plus algorithm and code are copied from the Wikipedia entry:
 * https://en.wikipedia.org/wiki/Xorshift
 * The algorithm was derived by Sebastiano Vigna from the original xorshift
 * algorithm designed by George Marsaglia.
 */

uint64_t RandGen::xorshift128plus(void)
{
    uint64_t x = state[0];
    uint64_t const y = state[1];
    state[0] = y;
    x ^= x << 23; // a
    state[1] = x ^ y ^ (x >> 17) ^ (y >> 26); // b, c
    return state[1] + y;
}
