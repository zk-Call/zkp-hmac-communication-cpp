#ifndef SEEDGENERATION_UTILS_BASE_H
// Preprocessor directive to ensure that this header file is included only once during compilation

#define SEEDGENERATION_UTILS_BASE_H
// Definition of the header guard macro to prevent multiple inclusions of the header file

#include <random>           // Include the header file for random number generation
#include <vector>           // Include the header file for vector containers
#include <openssl/sha.h>    // OpenSSL header for SHA hashing

// Function declaration to get a random integer
int get_random_int();

// Function declaration to compute the hash digest of a vector of unsigned characters
std::vector<unsigned char> hash_digest(const std::vector<unsigned char> &combined_bytes);

#endif //SEEDGENERATION_UTILS_BASE_H
// End of the header guard macro definition and the end of the header file
