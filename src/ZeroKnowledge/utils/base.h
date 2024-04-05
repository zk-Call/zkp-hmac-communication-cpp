#ifndef ZEROKNOWLEDGE_UTILS_BASE_H
// Preprocessor directive to ensure that this header file is included only once during compilation

#define ZEROKNOWLEDGE_UTILS_BASE_H
// Definition of the header guard macro to prevent multiple inclusions of the header file

#include <iostream>     // Standard I/O streams
#include <cstdint>      // Standard integer types

// Function declaration to convert a string of bytes to an unsigned 64-bit integer
uint64_t bytes_to_int(const std::string &bytes);

// Function declaration to perform modulo operation on two unsigned 64-bit integers
uint64_t mod(uint64_t a, uint64_t b);

// Function declaration to convert an unsigned 64-bit integer to a string of bytes
std::string int_to_bytes(uint64_t value);

#endif //ZEROKNOWLEDGE_UTILS_BASE_H
// End of the header guard macro definition and the end of the header file
