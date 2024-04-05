#ifndef ZEROKNOWLEDGE_CORE_BASE_H
// Preprocessor directive to ensure that this header file is included only once during compilation

#define ZEROKNOWLEDGE_CORE_BASE_H
// Definition of the header guard macro to prevent multiple inclusions of the header file

#include <chrono>           // Time utilities
#include <cstdint>          // Integer types with exact widths
#include <string>           // String utilities
#include <stdexcept>        // Standard exception objects
#include <random>           // Random number generation
#include <iostream>         // Input/output stream objects
#include <variant>          // Type-safe union alternative
#include <jwt-cpp/jwt.h>    // JWT library for JSON Web Tokens
#include <openssl/ec.h>     // OpenSSL library for Elliptic Curve Cryptography
#include <openssl/obj_mac.h>    // Object identifiers for EC curves
#include <openssl/ecdsa.h>  // ECDSA functions
#include <openssl/pem.h>    // PEM file format functions
#include <openssl/evp.h>    // High-level cryptographic functions
#include <openssl/err.h>    // Error handling functions
#include <openssl/rand.h>   // Random number generation functions
#include <openssl/sha.h>    // OpenSSL header for SHA-3 hashing
#include <nlohmann/json.hpp>   // JSON library

// Forward declaration of classes from other files
#include "../models/base.h"
#include "../utils//base.h"
#include "../algorithms/base.h"
#include "../types/curve/base.h"
#include "../types/point/base.h"

// Alias for JSON namespace
using json = nlohmann::json;
// Using directive to avoid writing nlohmann::json:: prefix

// Class definition for ZeroKnowledge
class ZeroKnowledge {
// Declaration of the ZeroKnowledge class
private:
    std::string secret;                 // Secret key for cryptographic operations
    std::string algorithm;              // Algorithm used for cryptographic operations
    std::string issuer;                 // Issuer of tokens
    ZeroKnowledgeParams params;         // Parameters for zero-knowledge protocols
    Curve obj_curve;                    // Object representing the elliptic curve

public:
    // Constructor for ZeroKnowledge class
    ZeroKnowledge(const ZeroKnowledgeParams &params, const std::string &sec, const std::string &alg, const std::string &iss);
    // Declaration of the constructor

    // Static method to create a new instance of ZeroKnowledge
    static ZeroKnowledge createNew(const std::string &curveName = "Ed25519", const std::string &hashAlg = "blake2b", const std::string &jwtSecret = "", const std::string &jwtAlg = "HB2B", int saltSize = 16);
    // Declaration of a static method to create a new instance of ZeroKnowledge

    // Method to generate a JWT token
    std::string token();
    // Declaration of a method to generate a JWT token

    // Method to generate a random salt
    static std::string generateSalt(int size);
    // Declaration of a static method to generate a random salt

    // Method to hash a string with a point
    uint64_t hash_with_point(const std::string &value, const Point &R);
    // Declaration of a method to hash a string with a point

    // Method to generate a JWT token
    std::string generateJWT(const ZeroKnowledgeSignature &signature, int expSeconds = 10);
    // Declaration of a method to generate a JWT token

    // Method to verify a JWT token
    bool verifyJWT(const std::string &token, const ZeroKnowledgeSignature &signature);
    // Declaration of a method to verify a JWT token

    // Method to verify a zero-knowledge proof
    bool verify(const ZeroKnowledgeData &challenge, const ZeroKnowledgeSignature &signature, const std::variant<std::string, ZeroKnowledgeProof> &data = "");
    // Declaration of a method to verify a zero-knowledge proof

    // Method to perform login using zero-knowledge authentication
    bool login(const ZeroKnowledgeData &login_data);
    // Declaration of a method to perform login using zero-knowledge authentication

    // Method to convert a variant value to a point
    Point to_point(const std::variant<int, std::string, std::vector<uint8_t>> &value);
    // Declaration of a method to convert a variant value to a point

    // Method to convert a BIGNUM value to uint64_t
    uint64_t bignum_to_uint64(const BIGNUM* bn);
    // Declaration of a method to convert a BIGNUM value to uint64_t

    // Method to create a zero-knowledge proof
    ZeroKnowledgeProof create_proof(const std::string &secret, const std::variant<int, std::string, std::vector<uint8_t>> &data);
    // Declaration of a method to create a zero-knowledge proof

    // Method to create a digital signature
    ZeroKnowledgeSignature createSignature(const std::string &data);
    // Declaration of a method to create a digital signature

    // Method to sign data using zero-knowledge authentication
    ZeroKnowledgeData sign(const std::string &secret, const std::variant<int, std::string, std::vector<uint8_t>> &data);
    // Declaration of a method to sign data using zero-knowledge authentication
};

#endif // ZEROKNOWLEDGE_CORE_BASE_H
// End of the header guard macro definition and the end of the header file
