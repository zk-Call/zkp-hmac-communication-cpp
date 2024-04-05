#include "base.h" // Assuming hash_digest() and get_random_int() functions are implemented in utils.h

// Constructor definition for SeedGenerator class
SeedGenerator::SeedGenerator(const std::string &phrase) : _phrase(phrase) {}
// Constructor initializes the _phrase member variable with the provided phrase

// Method to generate a hash
std::vector<unsigned char> SeedGenerator::_hash(int length) {
    // Create a vector to store combined bytes
    std::vector<unsigned char> combined_bytes(length + _phrase.size());

    // Secure random generation
    std::random_device rd;
    std::mt19937 gen(rd()); // Mersenne Twister pseudo-random generator engine
    std::uniform_int_distribution<unsigned char> dist(0, 255); // Distribution for random bytes

    // Fill the vector with random bytes
    for (int i = 0; i < length; ++i) {
        combined_bytes[i] = dist(gen); // Generate random byte and store in vector
    }

    // Append phrase bytes to the end of the vector
    std::copy(_phrase.begin(), _phrase.end(), combined_bytes.begin() + length);

    // Hash the combined bytes using hash_digest() function
    return hash_digest(combined_bytes);
}

// Method to generate a seed
std::vector<unsigned char> SeedGenerator::generate() {
    // Call the _hash method with a random length obtained from get_random_int() function
    return _hash(get_random_int());
}
