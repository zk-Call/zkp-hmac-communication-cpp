#ifndef ZEROKNOWLEDGE_ALGORITHMS_BASE_H
// Preprocessor directive to ensure that this header file is included only once during compilation

#define ZEROKNOWLEDGE_ALGORITHMS_BASE_H
// Definition of the header guard macro to prevent multiple inclusions of the header file

#include <iostream>     // Input/output stream objects
#include <cstdint>      // Integer types with exact widths
#include <openssl/sha.h>    // OpenSSL library for SHA hash functions

// Function declaration for hashing a string
uint64_t hash(const std::string &value);
// Declaration of the hash function to compute the hash of a string

#endif //ZEROKNOWLEDGE_ALGORITHMS_BASE_H
// End of the header guard macro definition and the end of the header file
