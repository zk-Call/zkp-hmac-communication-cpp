#include "base.h"
// Including the header file for the ZeroKnowledgeSignature class

ZeroKnowledgeSignature ZeroKnowledgeSignature::deserializeSignatureFromJson(const std::string &json_data) {
    // Parsing the input JSON data
    auto parsed_json = json::parse(json_data);

    // Creating a ZeroKnowledgeSignature object
    ZeroKnowledgeSignature signature;

    // Assuming the JSON structure contains params and signature fields
    // Assigning values from the parsed JSON to the signature object
    signature.params.curve = parsed_json["params"]["curve"];
    signature.params.salt = parsed_json["params"]["salt"];
    signature.params.algorithm = parsed_json["params"]["algorithm"];
    signature.signature = parsed_json["signature"];

    // Returning the deserialized signature object
    return signature;
}
