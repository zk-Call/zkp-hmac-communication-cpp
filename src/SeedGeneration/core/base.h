#ifndef SEEDGENERATION_CORE_BASE_H
// Preprocessor directive to ensure that this header file is included only once during compilation

#define SEEDGENERATION_CORE_BASE_H
// Definition of the header guard macro to prevent multiple inclusions of the header file

#include <string>           // String utilities
#include <random>           // Random number generation
#include "../utils/base.h" // Including header file for utility functions

// Declaration of the SeedGenerator class
class SeedGenerator {
public:
    // Constructor for SeedGenerator class
    SeedGenerator(const std::string& phrase);

    // Method to generate a seed
    std::vector<unsigned char> generate();

private:
    std::string _phrase;                        // Member variable to store the phrase
    std::vector<unsigned char> _hash(int length); // Method to generate a hash
};

#endif //SEEDGENERATION_CORE_BASE_H
// End of the header guard macro definition and the end of the header file
