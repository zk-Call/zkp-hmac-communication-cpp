#include "base.h"

// Function definition for Hash_type_and_len()
std::map<std::string, int> Hash_type_and_len() {
    // Create a map object to store hash types and their corresponding lengths
    std::map<std::string, int> obj;

    // Assign hash types and their lengths to the map
    obj["sha3_224"] = 56; // SHA-3 224-bit hash length
    obj["sha256"] = 64;   // SHA-256 hash length

    // Return the populated map
    return obj;
}
