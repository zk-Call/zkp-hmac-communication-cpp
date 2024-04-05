#include "base.h"
// Including the header file


// Function to convert a string of bytes to an unsigned 64-bit integer
uint64_t bytes_to_int(const std::string &bytes) {
    // Initialize the result to zero
    uint64_t result = 0;
    // Iterate over each byte in the input string
    for (size_t i = 0; i < bytes.size(); ++i) {
        // Extract each byte, convert it to an unsigned char, then shift it to the appropriate position
        // Combine the bytes using bitwise OR to form the resulting unsigned integer
        result |= (static_cast<uint64_t>(static_cast<unsigned char>(bytes[i])) << (8 * i));
    }
    // Return the resulting unsigned integer
    return result;
}

// Function to perform modulo operation on two unsigned 64-bit integers
uint64_t mod(uint64_t a, uint64_t b) {
    // Compute the positive modulo result and ensure it is within the range [0, b)
    return (a % b + b) % b;
}

// Function to convert an unsigned 64-bit integer to a string of bytes
std::string int_to_bytes(uint64_t value) {
    std::string result;
    // Extract each byte from the input value and append it to the result string
    while (value > 0) {
        // Extract the least significant byte using bitwise AND with 0xFF and convert it to char
        result.push_back(static_cast<char>(value & 0xFF));
        // Shift right by 8 bits to process the next byte
        value >>= 8;
    }
    // Return the resulting string of bytes
    return result;
}
