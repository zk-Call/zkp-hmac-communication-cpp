#include <iostream> // Include the input/output stream standard header
#include <thread> // Include the thread standard header
#include <queue> // Include the queue standard header
#include <string> // Include the string standard header
#include "src/Hmac/core/base.h" // Include the header file for HMAC_Client functionality
#include "src/SeedGeneration/core/base.h" // Include the header file for SeedGenerator functionality

constexpr bool DEBUG = true; // Define a constexpr boolean variable DEBUG with value true

void print_msg(const std::string &who, const std::string &message) { // Define a function to print messages
    if (DEBUG) { // Check if debugging is enabled
        std::cout << "[" << who << "] " << message << std::endl; // Print the message with source identifier
    }
}

bool check_if_queue_empty(std::queue<std::string> &socket) { // Define a function to check if a queue is empty
    while (true) { // Infinite loop
        if (!socket.empty()) { // Check if the queue is not empty
            return true; // Return true if the queue is not empty
        }
    }
}

std::string get_content_from_socket(std::queue<std::string> &socket) { // Define a function to get content from a socket (queue)
    if (check_if_queue_empty(socket)) { // Check if the queue is not empty
        std::string val = socket.front(); // Get the front element of the queue
        socket.pop(); // Remove the front element from the queue
        return val; // Return the retrieved value
    }
}

void client(std::queue<std::string> &client_socket, std::queue<std::string> &server_socket) { // Define the client function
    // Generating the main seed
    SeedGenerator seed_generator("job"); // Create an instance of SeedGenerator
    std::vector<unsigned char> main_seed = seed_generator.generate(); // Generate the main seed

    // Creating an instance of HMAC_Client for encrypting messages
    print_msg("client", "first");
    HMAC_Client obj("sha256", main_seed, 1); // Create an instance of HMAC_Client

    // Sending the main seed to the server
    server_socket.emplace(main_seed.begin(), main_seed.end()); // Convert the main seed vector to a string and send it to the server
    print_msg("client", "after obj");

    // Checking if the server has successfully received the seed
    if (get_content_from_socket(client_socket) == obj.encrypt_message("")) { // Check if the server received the seed
        print_msg("client", "after if");

        // If successful, send a message to the server
        std::string message = "hello"; // Define the message to be sent
        server_socket.push(obj.encrypt_message_by_chunks(message)); // Encrypt and send the message to the server
        print_msg("client", "client sent message " + message);

        // Checking if the server has successfully decrypted the message
        if (get_content_from_socket(client_socket) == obj.encrypt_message(message)) { // Check if the server decrypted the message
            print_msg("client", "server has decrypted message");
        }
    }
}

void server(std::queue<std::string> &server_socket, std::queue<std::string> &client_socket) { // Define the server function
    // Receiving the main seed from the client
    std::string main_seed = get_content_from_socket(server_socket); // Receive the main seed from the client

    // Creating an instance of HMAC_Client for encrypting messages
    HMAC_Client obj("sha256", std::vector<unsigned char>(main_seed.begin(), main_seed.end()), 1); // Create an instance of HMAC_Client

    // Sending an empty message to the client as acknowledgment
    client_socket.push(obj.encrypt_message("")); // Encrypt and send an empty message to the client as acknowledgment

    // Receiving the encrypted message from the client
    std::string msg = get_content_from_socket(server_socket); // Receive the encrypted message from the client
    print_msg("server", "message encrypted: " + msg);

    // Decrypting the message
    print_msg("server", "before decrypt ");
    std::string msg_raw = obj.decrypt_message_by_chunks(msg); // Decrypt the received message
    print_msg("server", "message raw: " + msg_raw);

    // Sending the encrypted message back to the client
    client_socket.push(obj.encrypt_message(msg_raw)); // Encrypt and send the decrypted message back to the client
}

int main() { // Main function
    std::queue<std::string> client_socket, server_socket; // Create queues for client and server sockets
    std::thread client_thread(client, std::ref(client_socket), std::ref(server_socket)); // Create a thread for the client function
    std::thread server_thread(server, std::ref(server_socket), std::ref(client_socket)); // Create a thread for the server function

    // Joining the threads to wait for their completion
    client_thread.join(); // Wait for the client thread to finish
    server_thread.join(); // Wait for the server thread to finish

    return 0; // Return 0 to indicate successful execution
}
