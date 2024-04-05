#ifndef HMAC_ALGORITHMS_BASE_H
// Preprocessor directive to ensure that this header file is included only once during compilation

#define HMAC_ALGORITHMS_BASE_H
// Definition of the header guard macro to prevent multiple inclusions of the header file

#include <map>          // Include the header file for the map container
#include <string>       // Include the header file for string utilities
#include <iostream>     // Include the header file for input/output stream objects

// Function declaration for Hash_type_and_len()
std::map<std::string, int> Hash_type_and_len();

#endif //HMAC_ALGORITHMS_BASE_H
// End of the header guard macro definition and the end of the header file
