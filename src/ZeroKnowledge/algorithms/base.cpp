#include "base.h"
// Including the header file that declares the hash function

// Function definition for hashing a string using SHA-3 algorithm
uint64_t hash(const std::string &value) {
    // Calculate SHA-3 hash
    unsigned char hashOutput[SHA512_DIGEST_LENGTH];  // Buffer to store hash output
    SHA512_CTX ctx;  // SHA-512 context structure
    SHA512_Init(&ctx);  // Initialize SHA-512 context
    SHA512_Update(&ctx, value.c_str(), value.length());  // Update context with input data
    SHA512_Final(hashOutput, &ctx);  // Finalize hashing and store the result in hashOutput

    // Convert the hash output to uint64_t
    uint64_t hashValue = 0;  // Variable to store final hash value
    for (size_t i = 0; i < SHA512_DIGEST_LENGTH && i < sizeof(hashValue); ++i) {
        // Combine bytes from hashOutput into hashValue
        hashValue |= (static_cast<uint64_t>(hashOutput[i]) << (8 * i));
    }

    return hashValue;  // Return the final hash value
}
