#include "base.h"

// Function to generate a random integer
int get_random_int() {
    std::random_device rd; // Obtain a random seed from the operating system's random device
    std::mt19937 gen(rd()); // Initialize the Mersenne Twister pseudo-random number generator with the obtained seed
    std::uniform_int_distribution<int> dist(0, (1 << 20) - 1); // Define a uniform distribution over the range [0, 2^20)
    return dist(gen); // Generate a random integer within the defined range and return it
}

// Function to compute the SHA-256 hash digest
std::vector<unsigned char> hash_digest(const std::vector<unsigned char> &combined_bytes) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH); // Initialize a vector to store the hash digest

    SHA256_CTX sha256; // Declare a SHA-256 context structure
    SHA256_Init(&sha256); // Initialize the SHA-256 context
    SHA256_Update(&sha256, combined_bytes.data(), combined_bytes.size()); // Update the SHA-256 context with the input data
    SHA256_Final(hash.data(), &sha256); // Finalize the hashing process and store the hash digest in the vector

    return hash; // Return the computed hash digest
}
