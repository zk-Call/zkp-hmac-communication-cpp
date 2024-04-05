#ifndef HMAC_UTILS_BASE_H // Preprocessor directive: ifndef checks if the identifier HMAC_UTILS_BASE_H has not been defined before
#define HMAC_UTILS_BASE_H // Preprocessor directive: defines the identifier HMAC_UTILS_BASE_H

#include <string> // Include the string standard header
#include <vector> // Include the vector standard header
#include <cstring> // Include the cstring standard header (for C-style string manipulation)

template<typename T> // Declaration of a template function, taking a typename T as a parameter
std::string to_str(const T& data, const std::string& encoding = "utf-8"); // Declaration of a function named to_str that converts data to a string using the specified encoding (default is utf-8)

template<typename T> // Declaration of a template function, taking a typename T as a parameter
std::vector<unsigned char> to_bytes(const T& data, const std::string& encoding = "utf-8"); // Declaration of a function named to_bytes that converts data to a vector of unsigned chars using the specified encoding (default is utf-8)

#endif //HMAC_UTILS_BASE_H // End of the ifndef directive, comments that this is the end of the ifndef block
