#include "base.h" // Include the header file for the HMAC_Client class

// Constructor definition for HMAC_Client class
HMAC_Client::HMAC_Client(std::string algorithm, const std::vector<unsigned char>& secret, int symbol_count) :
        _algorithm(std::move(algorithm)), _secret(secret), _symbol_count(symbol_count) {
    init_decrypt_dict(); // Initialize the decryption dictionary
}

// Method to initialize the decryption dictionary
void HMAC_Client::init_decrypt_dict() {
    std::string all_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

    // Iterate through all characters
    for (char c : all_chars) {
        std::string key = encrypt_message(std::string(1, c)); // Encrypt the character (convert char to string)
        _decrypt_dict[key] = std::string(1, c); // Map the encrypted character to its original form
    }
}

// Method to encrypt a message by processing it in chunks
std::string HMAC_Client::encrypt_message_by_chunks(const std::string& message) {
    std::string encrypted_message;
    // Process the message in chunks
    for (size_t i = 0; i < message.length(); i += _symbol_count) {
        std::string chunk = message.substr(i, _symbol_count); // Extract a chunk of the message
        encrypted_message += encrypt_message(chunk); // Encrypt the chunk and append it to the encrypted message
    }
    return encrypted_message; // Return the encrypted message
}

// Method to encrypt a message
std::string HMAC_Client::encrypt_message(const std::string& message) {
    unsigned char digest[EVP_MAX_MD_SIZE]; // Buffer to store the digest
    unsigned int digest_len; // Length of the digest

    // Compute the HMAC digest using SHA-256 algorithm
    HMAC(EVP_sha256(), _secret.data(), _secret.size(), reinterpret_cast<const unsigned char *>(message.c_str()),
         message.length(), digest, &digest_len);

    // Convert the digest to a hexadecimal string
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < digest_len; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(digest[i]);
    }

    return ss.str(); // Return the hexadecimal string representing the digest
}

// Method to decrypt a message by processing it in chunks
std::string HMAC_Client::decrypt_message_by_chunks(const std::string& message) {
    std::string msg_raw; // Variable to store the raw message
    int chunk_len = Hash_type_and_len()["sha256"]; // Get the length of a single chunk

    // Check if the message length is divisible by the chunk length
    if (message.length() % chunk_len == 0) {
        // Process the message in chunks
        for (size_t i = 0; i < message.length(); i += chunk_len) {
            std::string chunk = message.substr(i, chunk_len); // Extract a chunk of the message
            msg_raw += decrypt_message(chunk); // Decrypt the chunk and append it to the raw message
        }
        return msg_raw; // Return the raw message
    } else {
        // If the message length is not divisible by the chunk length, throw an exception
        throw std::invalid_argument("The algorithm is invalid: " + _algorithm);
    }
}

// Method to decrypt a message
std::string HMAC_Client::decrypt_message(const std::string& message) {
    auto it = _decrypt_dict.find(message); // Find the encrypted message in the decryption dictionary
    if (it != _decrypt_dict.end()) {
        return it->second; // Return the corresponding original message if found
    } else {
        // If the encrypted message is not found in the decryption dictionary, throw an exception
        throw std::invalid_argument("The algorithm is invalid: " + _algorithm);
    }
}
