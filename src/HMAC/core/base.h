#ifndef HMAC_CORE_BASE_H
// Preprocessor directive to ensure that this header file is included only once during compilation

#define HMAC_CORE_BASE_H
// Definition of the header guard macro to prevent multiple inclusions of the header file

#include <string>               // Include the header file for string utilities
#include <vector>               // Include the header file for vector containers
#include <map>                  // Include the header file for map containers
#include <openssl/hmac.h>       // Include the header file for HMAC related functions
#include <algorithm>            // Include the header file for algorithms
#include <stdexcept>            // Include the header file for standard exception objects
#include <openssl/evp.h>        // Include the header file for OpenSSL's EVP functions
#include <iomanip>              // Include the header file for input/output manipulators
#include <sstream>              // Include the header file for string streams
#include "../algorithms/base.h" // Include the header file for base algorithms

// Class declaration for HMAC_Client
class HMAC_Client {
private:
    std::string _algorithm;                     // Member variable to store the HMAC algorithm
    std::vector<unsigned char> _secret;         // Member variable to store the secret key
    std::map<std::string, std::string> _decrypt_dict; // Member variable to store decryption dictionary
    int _symbol_count;                          // Member variable to store symbol count

public:
    // Constructor for HMAC_Client class
    HMAC_Client(std::string algorithm = "sha256", const std::vector<unsigned char>& secret = {}, int symbol_count = 1);

    // Method to initialize the decryption dictionary
    void init_decrypt_dict();

    // Method to encrypt a message by processing it in chunks
    std::string encrypt_message_by_chunks(const std::string& message);

    // Method to encrypt a message
    std::string encrypt_message(const std::string& message);

    // Method to decrypt a message by processing it in chunks
    std::string decrypt_message_by_chunks(const std::string& message);

    // Method to decrypt a message
    std::string decrypt_message(const std::string& message);
};

#endif //HMAC_CORE_BASE_H
// End of the header guard macro definition and the end of the header file
