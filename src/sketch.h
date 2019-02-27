#ifndef _SKETCH_H_
#define _SKETCH_H_ 1

#include <vector>
#include <stdint.h>

std::vector<uint64_t> FindOddSyndromes(const std::vector<uint64_t>& data, int syndromes);
std::vector<uint64_t> ReconstructAllSyndromes(const std::vector<uint64_t>& odd_syndromes);
std::vector<uint64_t> AddSets(const std::vector<uint64_t>& basic_set, const std::vector<uint64_t>& add_set);
uint64_t EvalInPoly(const std::vector<uint64_t>& poly, uint64_t x0);
std::vector<uint64_t> BerlekampMassey(const std::vector<uint64_t>& syndromes);
std::vector<uint64_t> DecodeSyndromesExtGCD(std::vector<uint64_t> syndromes);
bool FindRoots(const std::vector<uint64_t>& poly, std::vector<uint64_t>& roots);
bool CancelOutAndFindRoots(const std::vector<uint64_t>& poly, std::vector<uint64_t>& roots, const std::vector<uint64_t>& suspects);

#endif
