#include "base.h" // Include the header file "base.h"

template<typename T> // Definition of a template function, taking a typename T as a parameter
std::string to_str(const T& data, const std::string& encoding) { // Definition of the function to_str, which converts data to a string using the specified encoding
    if constexpr (std::is_same_v<T, std::string>) { // Conditional compilation based on whether T is std::string
        return data; // Return the input data directly if it's already a string
    } else if constexpr (std::is_same_v<T, std::vector<unsigned char>>) { // Conditional compilation based on whether T is std::vector<unsigned char>
        return std::string(data.begin(), data.end()); // Return a string constructed from the vector of unsigned chars
    } else if constexpr (std::is_same_v<T, const char*>) { // Conditional compilation based on whether T is const char*
        return std::string(data); // Return a string constructed from the C-style string
    } else if constexpr (std::is_same_v<T, const unsigned char*>) { // Conditional compilation based on whether T is const unsigned char*
        return std::string(reinterpret_cast<const char*>(data)); // Return a string constructed from the pointer to unsigned chars, cast to a const char*
    } else if constexpr (std::is_integral_v<T>) { // Conditional compilation based on whether T is an integral type
        return std::to_string(data); // Return a string representation of the integral value
    } else if constexpr (std::is_floating_point_v<T>) { // Conditional compilation based on whether T is a floating-point type
        return std::to_string(data); // Return a string representation of the floating-point value
    } else if constexpr (std::is_same_v<T, bool>) { // Conditional compilation based on whether T is bool
        return data ? "true" : "false"; // Return "true" or "false" depending on the boolean value
    } else {
        static_assert(std::is_same_v<T, void>, "Unsupported type for to_str()"); // If none of the above conditions match, trigger a static assertion indicating unsupported type for to_str()
    }
}

template<typename T> // Definition of a template function, taking a typename T as a parameter
std::vector<unsigned char> to_bytes(const T& data, const std::string& encoding) { // Definition of the function to_bytes, which converts data to a vector of unsigned chars using the specified encoding
    if constexpr (std::is_same_v<T, std::string>) { // Conditional compilation based on whether T is std::string
        return std::vector<unsigned char>(data.begin(), data.end()); // Return a vector of unsigned chars constructed from the string
    } else if constexpr (std::is_same_v<T, const char*>) { // Conditional compilation based on whether T is const char*
        return std::vector<unsigned char>(data, data + strlen(data)); // Return a vector of unsigned chars constructed from the C-style string
    } else if constexpr (std::is_same_v<T, const unsigned char*>) { // Conditional compilation based on whether T is const unsigned char*
        return std::vector<unsigned char>(data, data + strlen(reinterpret_cast<const char*>(data))); // Return a vector of unsigned chars constructed from the pointer to unsigned chars, cast to a const char*
    } else if constexpr (std::is_integral_v<T>) { // Conditional compilation based on whether T is an integral type
        std::string str = std::to_string(data); // Convert the integral value to a string
        return std::vector<unsigned char>(str.begin(), str.end()); // Return a vector of unsigned chars constructed from the string
    } else if constexpr (std::is_floating_point_v<T>) { // Conditional compilation based on whether T is a floating-point type
        std::string str = std::to_string(data); // Convert the floating-point value to a string
        return std::vector<unsigned char>(str.begin(), str.end()); // Return a vector of unsigned chars constructed from the string
    } else if constexpr (std::is_same_v<T, bool>) { // Conditional compilation based on whether T is bool
        std::string str = data ? "true" : "false"; // Convert the boolean value to a string
        return std::vector<unsigned char>(str.begin(), str.end()); // Return a vector of unsigned chars constructed from the string
    } else {
        static_assert(std::is_same_v<T, void>, "Unsupported type for to_bytes()"); // If none of the above conditions match, trigger a static assertion indicating unsupported type for to_bytes()
    }
}
