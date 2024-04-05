#include "src/ZeroKnowledge/core/base.h" // Include the header file for ZeroKnowledge class

int main() { // Main function
    // Creating a ZeroKnowledge object for the client with specified curve and hash algorithm
    ZeroKnowledge clientObject = ZeroKnowledge::createNew("secp256k1", "sha3_256");

    // Creating a ZeroKnowledge object for the server with specified curve and hash algorithm
    ZeroKnowledge serverObject = ZeroKnowledge::createNew("secp384r1", "sha3_512");

    // Setting the server password
    std::string serverPassword = "SecretServerPassword";

    // Creating a signature for the server password
    ZeroKnowledgeSignature serverSignature = serverObject.createSignature(serverPassword);

    // Creating a signature for the client identity
    std::string identity = "John";
    ZeroKnowledgeSignature clientSignature = clientObject.createSignature(identity);
    std::cout<<"before\n";

    // Generating a token signed by the server for the client
    std::cout<<clientObject.token()<<"\n";

    ZeroKnowledgeData token = serverObject.sign(serverPassword, clientObject.token());
    std::cout<<"after\n";

    // Generating proof using client identity and token
    ZeroKnowledgeData proof = clientObject.sign(identity, token.data);

    // Verifying the received proof
    bool serverVerification = serverObject.verify(token, serverSignature);
    if (!serverVerification) { // Check if server verification failed
        std::cout << "Server verification failed" << std::endl; // Print error message
    } else { // If server verification succeeded
        // Otherwise, verify the proof using client signature
        bool clientVerification = clientObject.verify(token, clientSignature, proof.proof);
        if (!clientVerification) { // Check if client verification failed
            std::cout << "Client verification failed" << std::endl; // Print error message
        } else { // If client verification succeeded
            std::cout << "Authentication successful" << std::endl; // Print success message
        }
    }

    return 0; // Return 0 to indicate successful execution
}
