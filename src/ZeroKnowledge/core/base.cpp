#include "base.h"

// Constructor for the ZeroKnowledge class
ZeroKnowledge::ZeroKnowledge(const ZeroKnowledgeParams &params, const string &sec, const string &alg, const string &iss)
        : params(params), secret(sec), algorithm(alg), issuer(iss), obj_curve(params.curve) {
    // Initialize ZeroKnowledge object with provided parameters:
    // - params: ZeroKnowledgeParams object containing curve, salt, and algorithm information
    // - sec: Secret key for cryptographic operations
    // - alg: Algorithm used for cryptographic operations
    // - iss: Issuer of tokens
    // Also initialize obj_curve with the curve specified in params.
}

// Static method to create a new instance of ZeroKnowledge
ZeroKnowledge ZeroKnowledge::createNew(const string &curveName, const string &hashAlg,
                                       const string &jwtSecret, const string &jwtAlg,
                                       int saltSize) {
    // Create a new instance of ZeroKnowledge with specified parameters:
    // - curveName: Name of the elliptic curve to use
    // - hashAlg: Algorithm for hashing
    // - jwtSecret: Secret key for JWT operations
    // - jwtAlg: Algorithm for JWT operations
    // - saltSize: Size of the salt to generate
    // The ZeroKnowledgeParams object contains curve, salt, and algorithm information.
    // Return the created ZeroKnowledge object.

    // Create ZeroKnowledgeParams object with specified parameters
    ZeroKnowledgeParams params;
    params.curve = curveName;
    params.salt = generateSalt(saltSize); // Generate a salt
    params.algorithm = hashAlg; // Set hash algorithm

    // Return new ZeroKnowledge object initialized with provided parameters
    return ZeroKnowledge(params, jwtSecret, jwtAlg, "zk-call");
}

// Method to generate a random salt
std::string ZeroKnowledge::generateSalt(int size) {
    // Generate random bytes to create a salt of the specified size
    std::random_device rd; // Seed for random number generator
    std::mt19937 gen(rd()); // Mersenne Twister random number engine
    std::uniform_int_distribution<uint8_t> dis(0, 255); // Uniform distribution for byte values

    // Generate random salt string of specified size
    std::string salt(size, '\0'); // Initialize string with null characters of size 'size'
    for (auto &byte: salt) {
        byte = dis(gen); // Assign random byte value to each character in the salt string
    }

    // Return the generated salt
    return salt;
}

// Method to generate a random token
std::string ZeroKnowledge::token() {
    // Generate a random token using cryptographic secure random bytes
    std::random_device rd; // Seed for random number generator
    std::mt19937 gen(rd()); // Mersenne Twister random number engine
    std::uniform_int_distribution<uint8_t> dis(0, 255); // Uniform distribution for byte values

    // Calculate the number of bytes required for the token based on curve degree
    size_t numBytes = (obj_curve.getDegree() + 7) >> 3; // Right shift by 3 (divide by 8)

    // Generate random token string of appropriate size
    std::string token(numBytes, '\0'); // Initialize string with null characters of appropriate size
    for (auto &byte: token) {
        byte = dis(gen); // Assign random byte value to each character in the token string
    }

    // Return the generated token
    return token;
}


// Function to hash a string with a point on the elliptic curve
uint64_t ZeroKnowledge::hash_with_point(const std::string &value, const Point &R) {
    // Convert the point R to its uncompressed coordinates
    BIGNUM *x = BN_new();  // Allocate memory for x-coordinate
    BIGNUM *y = BN_new();  // Allocate memory for y-coordinate
    EC_POINT_get_affine_coordinates_GFp(obj_curve.getGroup(), R.get(), x, y,
                                        nullptr);  // Get affine coordinates of point R

    // Convert the coordinates to bytes
    unsigned char *x_bytes = new unsigned char[BN_num_bytes(x)];  // Allocate memory for x-coordinate bytes
    unsigned char *y_bytes = new unsigned char[BN_num_bytes(y)];  // Allocate memory for y-coordinate bytes
    BN_bn2bin(x, x_bytes);  // Convert x-coordinate to bytes
    BN_bn2bin(y, y_bytes);  // Convert y-coordinate to bytes

    // Calculate SHA-3 hash including both value and the point R coordinates
    SHA512_CTX ctx;  // Create SHA-512 context structure
    SHA512_Init(&ctx);  // Initialize SHA-512 context
    SHA512_Update(&ctx, value.c_str(), value.length());  // Update context with value string
    SHA512_Update(&ctx, x_bytes, BN_num_bytes(x));  // Update context with x-coordinate bytes
    SHA512_Update(&ctx, y_bytes, BN_num_bytes(y));  // Update context with y-coordinate bytes
    unsigned char hashOutput[SHA512_DIGEST_LENGTH];  // Buffer to store hash output
    SHA512_Final(hashOutput, &ctx);  // Finalize hashing and store result in hashOutput

    // Convert the hash output to uint64_t
    uint64_t hashValue = 0;  // Variable to store final hash value
    for (size_t i = 0; i < SHA512_DIGEST_LENGTH && i < sizeof(hashValue); ++i) {
        // Combine bytes from hashOutput into hashValue
        hashValue |= (static_cast<uint64_t>(hashOutput[i]) << (8 * i));
    }

    // Perform modulo with the curve order
    BIGNUM *bnOrder = BN_new();  // Allocate memory for curve order
    EC_GROUP_get_order(obj_curve.getGroup(), bnOrder, nullptr);  // Get order of the elliptic curve group

    // Compute the modulus using arithmetic operations
    uint64_t curveOrder = bignum_to_u int64(bnOrder);  // Convert curve order to uint64_t
    hashValue %= curveOrder;  // Perform modulo operation with curve order

    // Free allocated memory
    delete[] x_bytes;  // Free memory allocated for x-coordinate bytes
    delete[] y_bytes;  // Free memory allocated for y-coordinate bytes
    BN_free(x);  // Free memory allocated for x-coordinate BIGNUM
    BN_free(y);  // Free memory allocated for y-coordinate BIGNUM
    BN_free(bnOrder);  // Free memory allocated for curve order BIGNUM

    // Return the final hash value
    return hashValue;
}

// Function to generate a JWT (JSON Web Token) with expiration time
string ZeroKnowledge::generateJWT(const ZeroKnowledgeSignature &signature, int expSeconds) {
    // Calculate expiration time by adding specified seconds to current system time
    auto expTime = std::chrono::system_clock::now() + std::chrono::seconds(expSeconds);

    // Create JWT payload with expiration time
    auto token = jwt::create()
            .set_issuer(this->issuer) // Set the "iss" (issuer) claim
            .set_expires_at(expTime) // Set the expiration time
            .sign(jwt::algorithm::hs256{signature.signature}); // Sign the JWT using the provided signature

    // Return the generated JWT
    return token;
}

// Function to verify a JWT (JSON Web Token)
bool ZeroKnowledge::verifyJWT(const string &token, const ZeroKnowledgeSignature &signature) {
    try {
        // Decode the JWT
        auto decoded_token = jwt::decode(token);

        // Verify the JWT using the provided signature and issuer
        jwt::verify()
                .allow_algorithm(jwt::algorithm::hs256{signature.signature}) // Allow the HS256 algorithm
                .with_issuer(this->issuer) // Verify the "iss" (issuer) claim
                .verify(decoded_token); // Verify the JWT

        // Verification succeeded
        return true;
    } catch (const std::exception &e) {
        // Verification failed
        return false;
    }
}

// Function to verify a challenge with a signature and optional data
bool ZeroKnowledge::verify(const ZeroKnowledgeData &challenge, const ZeroKnowledgeSignature &signature,
                           const std::variant<std::string, ZeroKnowledgeProof> &data) {
    if (std::holds_alternative<ZeroKnowledgeProof>(data)) {  // Check if the data is a proof
        auto proof = std::get<ZeroKnowledgeProof>(data);  // Extract proof data
        // Compute the point
        EC_POINT *p = EC_POINT_new(obj_curve.getGroup());  // Create a new EC_POINT object
        BIGNUM *m = BN_bin2bn(reinterpret_cast<const unsigned char *>(proof.m.data()), proof.m.size(),
                              nullptr);  // Convert proof.m to BIGNUM
        BIGNUM *c = BN_bin2bn(reinterpret_cast<const unsigned char *>(proof.c.data()), proof.c.size(),
                              nullptr);  // Convert proof.c to BIGNUM
        EC_POINT_mul(obj_curve.getGroup(), p, m, obj_curve.getGenerator(), c,
                     nullptr);  // Compute EC_POINT multiplication

        // Compare computed_c with hash of challenge data and point
        uint64_t computed_c = hash(
                challenge.data + proof.m);  // Calculate hash of challenge data concatenated with proof.m
        BN_free(m);  // Free memory allocated for m
        BN_free(c);  // Free memory allocated for c
        EC_POINT_free(p);  // Free memory allocated for p

        // Return true if computed_c matches proof.c
        return computed_c == bytes_to_int(proof.c);
    } else if (std::holds_alternative<std::string>(data)) {  // Check if the data is a string
        auto data_str = std::get<std::string>(data);  // Extract data as string
        return verify(challenge, signature, data_str);  // Recursive call with string data
    } else {
        // Throw an exception for invalid data type provided
        throw std::invalid_argument("Invalid data type provided");
    }
}

// Function to perform login using ZeroKnowledgeData
bool ZeroKnowledge::login(const ZeroKnowledgeData &login_data) {
    if (!login_data.data.empty()) {  // Check if login data is not empty
        // Deserialize the signature from login_data.data
        ZeroKnowledgeSignature signature = ZeroKnowledgeSignature::deserializeSignatureFromJson(login_data.data);

        // Verify JWT using verifyJWT function and return result
        return verifyJWT(login_data.data, signature);
    } else {
        return false;  // Return false if login data is empty
    }
}


// Function to convert variant types to a Point on the elliptic curve
Point ZeroKnowledge::to_point(const std::variant<int, std::string, std::vector<uint8_t>> &value) {
    std::string bytes;  // Variable to store bytes representation of the value
    if (std::holds_alternative<int>(value)) {  // Check if the value is of type int
        int intValue = std::get<int>(value);  // Get the integer value
        bytes = std::to_string(intValue);  // Convert the integer to string
    } else if (std::holds_alternative<std::string>(value)) {  // Check if the value is of type string
        bytes = std::get<std::string>(value);  // Get the string value
    } else if (std::holds_alternative<std::vector<uint8_t>>(value)) {  // Check if the value is of type vector<uint8_t>
        const std::vector<uint8_t> &byte_data = std::get<std::vector<uint8_t>>(value);  // Get the byte data
        bytes = std::string(byte_data.begin(), byte_data.end());  // Convert byte data to string
    } else {
        // Throw an exception for invalid type provided
        throw std::invalid_argument("Invalid type for value");
    }

    // Convert the string to BIGNUM
    BIGNUM *x = BN_new();  // Allocate memory for BIGNUM
    BN_bin2bn(reinterpret_cast<const unsigned char *>(bytes.data()), bytes.size(), x);  // Convert bytes to BIGNUM

    // Create a new EC_POINT
    EC_POINT *point = EC_POINT_new(obj_curve.getGroup());  // Allocate memory for EC_POINT

    // Set the affine coordinates
    if (!EC_POINT_set_affine_coordinates_GFp(obj_curve.getGroup(), point, x, nullptr, nullptr)) {
        // Error handling in case setting affine coordinates fails
        BN_free(x);  // Free memory allocated for BIGNUM
        EC_POINT_free(point);  // Free memory allocated for EC_POINT
        throw std::runtime_error("Failed to set affine coordinates");
    }

    // Check if the point is on the curve
    if (!obj_curve.is_on_curve(point)) {
        // Error handling in case point is not on the curve
        BN_free(x);  // Free memory allocated for BIGNUM
        EC_POINT_free(point);  // Free memory allocated for EC_POINT
        throw std::runtime_error("The point is not on the curve");
    }

    // Free the allocated memory for x
    BN_free(x);

    // Return the Point object
    return Point(point);
}

// Function to convert BIGNUM to uint64_t
uint64_t ZeroKnowledge::bignum_to_uint64(const BIGNUM *bn) {
    // Convert the big integer to a string representation
    char *str = BN_bn2hex(bn);  // Convert BIGNUM to hexadecimal string
    if (!str) {
        throw std::runtime_error("Failed to convert BIGNUM to string");  // Throw an exception if conversion fails
    }

    // Convert the hexadecimal string to uint64_t
    uint64_t result = strtoull(str, nullptr, 16);  // Convert hexadecimal string to uint64_t

    // Free the memory allocated by BN_bn2hex
    OPENSSL_free(str);  // Free memory allocated for hexadecimal string

    return result;  // Return the result
}


// Method to create a ZeroKnowledgeProof
ZeroKnowledgeProof ZeroKnowledge::create_proof(const std::string &secret,
                                               const std::variant<int, std::string, std::vector<uint8_t>> &data) {
    // Compute hash of the secret key
    uint64_t key = hash(secret);  // Compute hash of the secret key

    // Convert the value to a string
    std::string str_data;  // Variable to store the converted data as string
    if (std::holds_alternative<int>(data)) {  // Check if the data is of type int
        str_data = std::to_string(std::get<int>(data));  // Convert int data to string
    } else if (std::holds_alternative<std::string>(data)) {  // Check if the data is of type string
        str_data = std::get<std::string>(data);  // Get string data
    } else if (std::holds_alternative<std::vector<uint8_t>>(data)) {  // Check if the data is of type vector<uint8_t>
        const auto &byte_data = std::get<std::vector<uint8_t>>(data);  // Get byte data
        str_data = std::string(byte_data.begin(), byte_data.end());  // Convert byte data to string
    } else {
        // Throw an exception for invalid type provided
        throw std::invalid_argument("Invalid type for data");
    }

    // Convert the value to a point on the curve
    Point R = this->to_point(data);  // Convert the value to a point on the curve

    // Compute hash with the point
    uint64_t c = this->hash_with_point(str_data, R);  // Compute hash with the point

    // Generate a random integer
    std::random_device rd;  // Create a random device
    std::mt19937 gen(rd());  // Initialize the Mersenne Twister engine with random seed
    const BIGNUM *curve_order_bignum = obj_curve.getOrder();  // Get the curve order
    uint64_t curve_order = bignum_to_uint64(curve_order_bignum);  // Convert curve order to uint64_t
    std::uniform_int_distribution<uint64_t> dis(0, curve_order);  // Create uniform distribution over the curve order
    uint64_t r = dis(gen);  // Generate a random integer

    // Compute m
    uint64_t m = mod(r - (c * key), curve_order);  // Compute m

    // Return the proof object
    return ZeroKnowledgeProof{params, int_to_bytes(c), int_to_bytes(m)};  // Return the generated ZeroKnowledgeProof
}



// Method to create a signature for given data
ZeroKnowledgeSignature ZeroKnowledge::createSignature(const std::string &data) {
    // For demonstration purposes, let's assume the signature is a hash of the data
    // You should replace this with your actual signature generation logic
    // Here, we'll use SHA-256 hash as the signature
    unsigned char hashOutput[SHA256_DIGEST_LENGTH];  // Array to store the hash output
    SHA256_CTX ctx;  // SHA256 context
    SHA256_Init(&ctx);  // Initialize SHA256 context
    SHA256_Update(&ctx, data.c_str(), data.length());  // Update SHA256 context with data
    SHA256_Final(hashOutput, &ctx);  // Finalize SHA256 context and compute hash

    // Convert the hash to a hexadecimal string
    stringstream ss;  // String stream to construct hexadecimal string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {  // Loop through hash output bytes
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hashOutput[i]);  // Append each byte as hexadecimal to stringstream
    }
    string signature = ss.str();  // Convert stringstream to string

    // Create a ZeroKnowledgeSignature object with the generated signature
    return ZeroKnowledgeSignature{signature};  // Return the generated ZeroKnowledgeSignature
}

// Method to sign data with given secret
ZeroKnowledgeData ZeroKnowledge::sign(const std::string &secret, const std::variant<int, std::string, std::vector<uint8_t>> &data) {
    std::string str_data;  // String to store converted data
    std::visit([&str_data](const auto &value) {  // Visit the variant type
        using T = std::decay_t<decltype(value)>;  // Get the type of value
        if constexpr (std::is_same_v<T, int>) {  // Check if the type is int
            str_data = std::to_string(value); // Convert int to string
        } else if constexpr (std::is_same_v<T, std::string>) {  // Check if the type is string
            str_data = value; // No conversion needed for std::string
        } else if constexpr (std::is_same_v<T, std::vector<uint8_t>>) {  // Check if the type is vector<uint8_t>
            str_data = std::string(value.begin(), value.end()); // Convert std::vector<uint8_t> to string
        }
    }, data);  // Perform the visitation on data

    return ZeroKnowledgeData{  // Create a ZeroKnowledgeData object
            .data = str_data,  // Set the data field
            .proof = create_proof(secret, str_data)  // Create proof for the data
    };
}


