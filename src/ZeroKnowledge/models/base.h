#ifndef ZEROKNOWLEDGE_MODELS_BASE_H
// Preprocessor directive to ensure that this header file is included only once during compilation

#define ZEROKNOWLEDGE_MODELS_BASE_H
// Definition of the header guard macro to prevent multiple inclusions of the header file

#include <nlohmann/json.hpp>
// Include the JSON library

using namespace std;
using json = nlohmann::json;
// Using directives to avoid writing std:: and nlohmann::json:: prefixes

class ZeroKnowledgeParams {
// Declaration of the ZeroKnowledgeParams class
public:
    std::string curve;
    // Member variable to store the name of the elliptic curve
    std::string salt;
    // Member variable to store the salt value
    std::string algorithm;
    // Member variable to store the algorithm name
};

class ZeroKnowledgeSignature {
// Declaration of the ZeroKnowledgeSignature class
public:
    ZeroKnowledgeParams params;
    // Member variable of type ZeroKnowledgeParams to store parameters
    std::string signature;
    // Member variable to store the signature

    // Static method to deserialize JSON data into ZeroKnowledgeSignature object
    static ZeroKnowledgeSignature deserializeSignatureFromJson(const std::string &json_data);
    // Declaration of a static method to deserialize JSON data into a ZeroKnowledgeSignature object
};

class ZeroKnowledgeProof {
// Declaration of the ZeroKnowledgeProof class
public:
    ZeroKnowledgeParams params;
    // Member variable of type ZeroKnowledgeParams to store parameters
    std::string c;
    // Member variable to store a value 'c'
    std::string m;
    // Member variable to store a value 'm'
};

class ZeroKnowledgeData {
// Declaration of the ZeroKnowledgeData class
public:
    std::string data;
    // Member variable to store data
    ZeroKnowledgeProof proof;
    // Member variable of type ZeroKnowledgeProof to store a proof
};

#endif //ZEROKNOWLEDGE_MODELS_BASE_H
// End of the header guard macro definition and the end of the header file
