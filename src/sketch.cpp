#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <vector>

#include <algorithm>

#if FIELD4
#include "field_4bit.h"
#elif FIELD40
#include "field_40bit.h"
#else
#include "field_64bit.h"
#endif

namespace {

//* Compute the remainder of a polynomial division of val by mod, putting the result in mod.
void Mod(const std::vector<uint64_t>& mod, std::vector<uint64_t>& val) {
    size_t modsize = mod.size();
    assert(modsize > 0 && mod.back() == 1);
    if (val.size() < modsize) return;
    assert(val.back() != 0);
    while (val.size() >= modsize) {
        uint64_t term = val.back();
        val.pop_back();
        if (term) {
            uint64_t table[TABLE_SIZE];
            precompute(term, table);
            for (size_t x = 0; x < mod.size() - 1; ++x) {
                val[val.size() - modsize + 1 + x] ^= fastmul(mod[x], table);
            }
        }
    }
    while (val.size() > 0 && val.back() == 0) val.pop_back();
}

/** Compute the quotient of a polynomial division of val by mod, putting the quotient in div and the remainder in val. */
void DivMod(const std::vector<uint64_t>& mod, std::vector<uint64_t>& val, std::vector<uint64_t>& div) {
    size_t modsize = mod.size();
    assert(mod.size() > 0 && mod.back() == 1);
    if (val.size() < mod.size()) {
        div.clear();
        return;
    }
    assert(val.back() != 0);
    div.resize(val.size() - mod.size() + 1);
    while (val.size() >= modsize) {
        uint64_t term = val.back();
        div[val.size() - modsize] = term;
        val.pop_back();
        if (term) {
            uint64_t table[TABLE_SIZE];
            precompute(term, table);
            for (size_t x = 0; x < mod.size() - 1; ++x) {
                val[val.size() - modsize + 1 + x] ^= fastmul(mod[x], table);
            }
        }
    }
}

/** Make a polynomial monic. */
uint64_t MakeMonic(std::vector<uint64_t>& a) {
    assert(a.back() != 0);
    if (a.back() == 1) return 0;
    uint64_t fac = inv(a.back());
    a.back() = 1;
    for (size_t i = 0; i < a.size() - 1; ++i) {
        a[i] = mul(a[i], fac);
    }
    return fac;
}

/** Compute the GCD of two polynomials, putting the result in a. b will be cleared. */
void GCD(std::vector<uint64_t>& a, std::vector<uint64_t>& b) {
    if (a.size() < b.size()) std::swap(a, b);
    while (b.size() > 0) {
        if (b.size() == 1) {
            a.resize(1);
            a[0] = 1;
            return;
        }
        MakeMonic(b);
        Mod(b, a);
        std::swap(a, b);
    }
}

void RemoveTrailingZeroes(std::vector<uint64_t>& a) {
    for (;;) {
        if (a.back() == 0)
            a.pop_back();
        else
            break;
    }
}

//    res = a * b - c
void MulAndSub(const std::vector<uint64_t>& a, const std::vector<uint64_t>& b, const std::vector<uint64_t>& c, std::vector<uint64_t>& res) {
    for (int i = 0; i < a.size(); i++) {
        uint64_t table[TABLE_SIZE];
        precompute(a[i], table);
        for (int j = 0; j < b.size(); j++) {
            res[i + j] ^= fastmul(b[j], table);
        }
    }
    for (int i = 0; i < c.size(); i++)
        res[i] ^= c[i];
}



/** Square a polynomial. */
void Sqr(std::vector<uint64_t>& poly) {
    if (poly.size() == 0) return;
    poly.resize(poly.size() * 2 - 1);
    for (int x = poly.size() - 1; x >= 0; --x) {
        poly[x] = (x & 1) ? 0 : sqr(poly[x / 2]);
    }
}

/** Compute the trace map of (param*x) modulo mod, putting the result in out. */
void TraceMod(const std::vector<uint64_t>& mod, std::vector<uint64_t>& out, uint64_t param) {
    out.reserve(mod.size() * 2);
    out.resize(2);
    out[0] = 0;
    out[1] = param;

    for (int i = 0; i < FIELD_SIZE - 1; ++i) {
        Sqr(out);
        if (out.size() < 2) out.resize(2);
        out[1] = param;
        Mod(mod, out);
    }
}

/** One step of the root finding algorithm; finds roots of stack[pos] and adds them to roots. Stack elements >= pos are destroyed. */
bool RecFindRoots(std::vector<std::vector<uint64_t>>& stack, size_t pos, std::vector<uint64_t>& roots, bool known_distinct) {
    if (pos + 3 > stack.size()) {
        stack.resize((pos + 3) * 2);
    }
    std::vector<uint64_t>& poly = stack[pos];
    std::vector<uint64_t>& tmp = stack[pos + 1];
    std::vector<uint64_t>& trace = stack[pos + 2];
    assert(poly.size() > 0 && poly.back() == 1);
    if (poly.size() == 1) return true;
    if (poly.size() == 2) {
        roots.push_back(poly[0]);
        return true;
    }
    trace.clear();
    tmp.clear();
    for (int iter = 0;; ++iter) {
        uint64_t r;
        do {
            r = rnd();
        } while (r == 0);
        TraceMod(poly, trace, r);

        if (iter == 1 && !known_distinct) {
            // Only check for distinct roots after a failed iteration
            tmp = trace;
            Sqr(tmp);
            for (size_t i = 0; i < trace.size(); ++i) {
                tmp[i] ^= trace[i];
            }
            while (tmp.size() && tmp.back() == 0) tmp.pop_back();
            Mod(poly, tmp);
            if (tmp.size() != 0) return false;
            known_distinct = true;
        }
        tmp = poly;
        GCD(trace, tmp);
        if (trace.size() != poly.size() && trace.size() > 1) break;
    }
    MakeMonic(trace);
    DivMod(trace, poly, tmp);
    // At this point, the stack looks like [... (poly) tmp trace], and we want to recursively
    // find roots of trace and tmp (= poly/trace). As we don't care about poly anymore, move
    // trace into its position first.
    std::swap(poly, trace);
    // Now the stack is [... (trace) tmp ...]. First we factor tmp (at pos = pos+1), and then
    // we factor trace (at pos = pos).
    if (!RecFindRoots(stack, pos + 1, roots, known_distinct)) return false;
    if (!RecFindRoots(stack, pos, roots, known_distinct)) return false;
    return true;
}

std::vector<uint64_t> Derivative(const std::vector<uint64_t>& a) {
    int even_degree = a.size() % 2;
    std::vector<uint64_t> res;
    for (int i = even_degree; i < a.size() - 1; i+=2) {
        res.push_back(a[i]);
        res.push_back(0);
    }
    while (res.size() && res.back() == 0) res.pop_back();
    return res;
}

bool IsSquareFree(const std::vector<uint64_t>& poly) {
    std::vector<uint64_t> der = Derivative(poly);
    auto copy = poly;
    GCD(copy, der);
    return copy.size() == 1 && copy[0] == 1;
}

}

std::vector<uint64_t> FindOddSyndromes(const std::vector<uint64_t>& data, int syndromes) {
    std::vector<uint64_t> ret;
    ret.resize(syndromes);

    for (uint64_t element : data) {
        uint64_t s = sqr(element);
        uint64_t table[TABLE_SIZE];
        precompute(s, table);
        ret[0] ^= element;
        for (int i = 1; i < syndromes; ++i) {
            element = fastmul(element, table);
            ret[i] ^= element;
        }
    }
    return ret;
}

std::vector<uint64_t> ReconstructAllSyndromes(const std::vector<uint64_t>& odd_syndromes) {
    std::vector<uint64_t> all_syndromes;
    all_syndromes.resize(odd_syndromes.size() * 2);
    for (size_t i = 0; i < odd_syndromes.size(); ++i) {
        all_syndromes[i * 2] = odd_syndromes[i];
        all_syndromes[i * 2 + 1] = sqr(all_syndromes[i]);
    }
    return all_syndromes;
}

std::vector<uint64_t> AddSets(const std::vector<uint64_t>& basic_set, const std::vector<uint64_t>& add_set) {
    std::vector<uint64_t> res;
    res.resize(basic_set.size());
    assert(basic_set.size() == add_set.size());
    for (size_t i = 0; i < basic_set.size(); ++i) {
        res[i] = basic_set[i] ^ add_set[i];
    }
    return res;
}

uint64_t EvalInPoly(const std::vector<uint64_t>& poly, uint64_t x0) {
    uint64_t table[TABLE_SIZE];
    uint64_t res = poly[0];
    precompute(x0, table);
    for (size_t i = 1 ; i < poly.size(); i++) {
        res = poly[i] ^ fastmul(res, table);
    }
    return res;
}

std::vector<uint64_t> BerlekampMassey(const std::vector<uint64_t>& syndromes) {
    std::vector<uint64_t> current, prev, tmp;
    current.reserve(syndromes.size() / 2 + 1);
    prev.reserve(syndromes.size() / 2 + 1);
    tmp.reserve(syndromes.size() / 2 + 1);
    current.resize(1);
    current[0] = 1;
    prev.resize(1);
    prev[0] = 1;
    uint64_t b = 1, b_inv = 1;

    for (size_t n = 0; n != syndromes.size(); ++n) {
        uint64_t discrepancy = syndromes[n];
        for (int i = 1; i < current.size(); ++i) discrepancy ^= mul(current[i], syndromes[n - i]);
        if (discrepancy != 0) {
            int x = n + 1 - (current.size() - 1) - (prev.size() - 1);
            uint64_t table[TABLE_SIZE];
            if (b_inv == 0) b_inv = inv(b);
            precompute(mul(discrepancy, b_inv), table);
            if (2 * (current.size() - 1) > n) {
                for (size_t i = 0; i < prev.size(); ++i) current[i + x] ^= fastmul(prev[i], table);
            } else {
                tmp = current;
                current.resize(prev.size() + x);
                for (size_t i = 0; i < prev.size(); ++i) current[i + x] ^= fastmul(prev[i], table);
                std::swap(prev, tmp);
                b = discrepancy;
                b_inv = 0;
            }
        }
    }
    assert(current.size() <= syndromes.size() / 2 + 1);
    assert(current.size() && current.back() != 0);
    return current;
}

std::vector<uint64_t> DecodeSyndromesExtGCD(std::vector<uint64_t> syndromes) {
    uint64_t d = syndromes.size() + 1;
    std::vector<uint64_t> Rold(d, 0);
    Rold[d-1] = 1;
    auto Rcur = syndromes;
    std::vector<uint64_t> Vold;
    std::vector<uint64_t> Vcur = {1};
    uint64_t t = (d - 1) / 2;
    std::vector<uint64_t> q(syndromes.size());
    while (Rcur.size() >=  t) {
        // Rold = Rcur*q + Rnew
        auto RoldCopy = Rold;
        uint64_t fac = MakeMonic(Rcur);

        DivMod(Rcur, RoldCopy, q);
        auto Rnew = RoldCopy;

        uint64_t fac_table[TABLE_SIZE];
        precompute(fac, fac_table);

        for (int i = 0; i < Rnew.size(); i++)
            Rnew[i] = fastmul(Rnew[i], fac_table);

        for (int i = 0; i < q.size(); i++)
            q[i] = fastmul(q[i], fac_table);

        // Vnew = Vold - qVcur)
        std::vector<uint64_t> Vnew(std::max(Vcur.size() + q.size() - 1, Vold.size()), 0);
        MulAndSub(Vcur, q, Vold, Vnew);

        Rcur.swap(Rold);
        Rnew.swap(Rcur);

        Vcur.swap(Vold);
        Vnew.swap(Vcur);

        RemoveTrailingZeroes(Rcur);
    }
    return Vcur;
}


/** Find roots of poly and put them in roots. Poly must be square free and only have 1st degree factors. */
bool FindRoots(const std::vector<uint64_t>& poly, std::vector<uint64_t>& roots) {
    if (!IsSquareFree(poly)) {
        return false;
    }
    roots.clear();
    roots.reserve(poly.size());
    std::vector<std::vector<uint64_t>> stack = {poly};
    return RecFindRoots(stack, 0, roots, false);
}

bool CancelOutAndFindRoots(const std::vector<uint64_t>& poly, std::vector<uint64_t>& roots, const std::vector<uint64_t>& suspects) {
    std::vector<uint64_t> pre_checked_roots;
    auto poly_without_suspects = poly;
    std::vector<uint64_t> copy;
    const int stop = poly.size() * 0.1;
//    const int stop = 1;
    for (int i = 0; i < suspects.size(); i++) {
        if (poly_without_suspects.size() == stop) break;
        uint64_t table[TABLE_SIZE];
        precompute(suspects[i], table);
        copy.resize(poly_without_suspects.size() - 1);
        uint64_t eval = 0;
        for (ssize_t pos = poly_without_suspects.size() - 1; pos >= 1; --pos) {
            eval = fastmul(eval, table) ^ poly_without_suspects[pos];
            copy[pos - 1] = eval;
        }
        if (fastmul(eval, table) == poly_without_suspects[0]) {
            pre_checked_roots.push_back(suspects[i]);
            std::swap(copy, poly_without_suspects);
        }
    }
    bool res = FindRoots(poly_without_suspects, roots);
    roots.insert(roots.end(), pre_checked_roots.begin(), pre_checked_roots.end());

    return res;
}
