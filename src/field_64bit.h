#ifndef _FIELD_64BIT_H_
#define _FIELD_64BIT_H_ 1

#include <inttypes.h>

#ifdef USE_CLMUL
#include <x86intrin.h>
#define TABLE_SIZE 1
#else
#define TABLE_SIZE 416
#endif

#define FIELD_SIZE 64
#define MODULO_LOW_BITS 27
#define FIELD_MASK 0xffffffffffffffff

namespace {

/** Multiply a field element with 2. */
constexpr uint64_t mul2(uint64_t x) {
    return ((x << 1) ^ (((uint64_t)(-(x >> (FIELD_SIZE - 1)))) & MODULO_LOW_BITS));
}

#ifdef USE_CLMUL
uint64_t reduce(__m128i a) {
    const __m128i LOW_MODULO = _mm_set_epi64x(0, ((uint64_t)MODULO_LOW_BITS));
    __m128i result = a;

    __m128i product2 = _mm_clmulepi64_si128(LOW_MODULO, a, 0xF2);
    result = _mm_xor_si128(result, product2);
    __m128i product3 = _mm_clmulepi64_si128(LOW_MODULO, product2, 0xF2);

    result = _mm_xor_si128(result, product3);
    return _mm_cvtsi128_si64(result);
}

uint64_t mul(uint64_t a, uint64_t b) {
    __m128i a1 = _mm_cvtsi64_si128(a);
    __m128i b1 = _mm_cvtsi64_si128(b);

    __m128i product = _mm_clmulepi64_si128(a1, b1, 0x00);
    return reduce(product);
}

/** Precompute a table of 256 multiples of x to speed up multiplication. */
void precompute(uint64_t x, uint64_t* table) {
    table[0] = x;
}

uint64_t fastmul(uint64_t x, const uint64_t* table) {
    return mul(x, table[0]);
}
#else
/** Multiply two field elements. */
uint64_t mul(uint64_t a, uint64_t b) {
    uint64_t r = 0;
    for (int i = 0; i < FIELD_SIZE; ++i) {
        r ^= (1 + ~(b & 1)) & a; a = mul2(a); b >>= 1;
    }
    return r;
}

/** Multiply a field element with another, specified by its precomputation table. */
constexpr uint64_t fastmul(uint64_t b, const uint64_t* table) {
    return table[0x00 + ((b >>  0) & 31)]  ^ table[0x20 + ((b >>  5) & 31)] ^  table[0x40 + ((b >> 10) & 31)]  ^ table[0x60 + ((b >> 15) & 31)] ^
           table[0x80 + ((b >> 20) & 31)]  ^ table[0xA0 + ((b >> 25) & 31)] ^  table[0xC0 + ((b >> 30) & 31)]  ^ table[0xE0 + ((b >> 35) & 31)] ^
           table[0x100 + ((b >> 40) & 31)] ^ table[0x120 + ((b >> 45) & 31)] ^ table[0x140 + ((b >> 50) & 31)] ^ table[0x160 + ((b >> 55) & 31)] ^
           table[0x180 + ((b >> 60) & 31)];
}

/** Precompute a table of 416 multiples of x to speed up multiplication. */
void precompute(uint64_t x, uint64_t* table) {
    for (int i = 0; i < 13; ++i) {
        uint64_t x1 = x; x = mul2(x);
        uint64_t x2 = x; x = mul2(x);
        uint64_t x4 = x; x = mul2(x);
        uint64_t x8 = x; x = mul2(x);
        uint64_t x16 = x; x = mul2(x);
        *(table++) = 0;
        *(table++) = x1;
        *(table++) = x2;
        *(table++) = x1 ^ x2;
        *(table++) = x4;
        *(table++) = x4 ^ x1;
        *(table++) = x4 ^ x2;
        *(table++) = x4 ^ x2 ^ x1;
        *(table++) = x8;
        *(table++) = x8 ^ x1;
        *(table++) = x8 ^ x2;
        *(table++) = x8 ^ x2 ^ x1;
        *(table++) = x8 ^ x4;
        *(table++) = x8 ^ x4 ^ x1;
        *(table++) = x8 ^ x4 ^ x2;
        *(table++) = x8 ^ x4 ^ x2 ^ x1;
        *(table++) = x16;
        *(table++) = x16 ^ x1;
        *(table++) = x16 ^ x2;
        *(table++) = x16 ^ x1 ^ x2;
        *(table++) = x16 ^ x4;
        *(table++) = x16 ^ x4 ^ x1;
        *(table++) = x16 ^ x4 ^ x2;
        *(table++) = x16 ^ x4 ^ x2 ^ x1;
        *(table++) = x16 ^ x8;
        *(table++) = x16 ^ x8 ^ x1;
        *(table++) = x16 ^ x8 ^ x2;
        *(table++) = x16 ^ x8 ^ x2 ^ x1;
        *(table++) = x16 ^ x8 ^ x4;
        *(table++) = x16 ^ x8 ^ x4 ^ x1;
        *(table++) = x16 ^ x8 ^ x4 ^ x2;
        *(table++) = x16 ^ x8 ^ x4 ^ x2 ^ x1;
    }
}

#endif

uint64_t sqr(uint64_t x) {
    return mul(x, x);
}

uint64_t sqrt(uint64_t a) {
    for (int i = 0; i < FIELD_SIZE - 1; ++i) a = sqr(a);
    return a;
}

uint64_t inv(uint64_t x1) {
    uint64_t x2 = x1;
    for (int i = 0; i < 1; ++i) x2 = sqr(x2);
    x2 = mul(x2, x1);
    uint64_t x4 = x2;
    for (int i = 0; i < 2; ++i) x4 = sqr(x4);
    x4 = mul(x4, x2);
    uint64_t x8 = x4;
    for (int i = 0; i < 4; ++i) x8 = sqr(x8);
    x8 = mul(x8, x4);
    uint64_t x16 = x8;
    for (int i = 0; i < 8; ++i) x16 = sqr(x16);
    x16 = mul(x16, x8);
    uint64_t x32 = x16;
    for (int i = 0; i < 16; ++i) x32 = sqr(x32);
    x32 = mul(x32, x16);
    uint64_t r = x32;
    for (int i = 0; i < 16; ++i) r = sqr(r);
    r = mul(r, x16);
    for (int i = 0; i < 8; ++i) r = sqr(r);
    r = mul(r, x8);
    for (int i = 0; i < 4; ++i) r = sqr(r);
    r = mul(r, x4);
    for (int i = 0; i < 2; ++i) r = sqr(r);
    r = mul(r, x2);
    for (int i = 0; i < 1; ++i) r = sqr(r);
    r = mul(r, x1);
    return sqr(r);
}

uint64_t rnd() {
    return (((uint64_t)random()) << 44) ^ (((uint64_t)random()) << 22) ^ random();
}

}

#endif
