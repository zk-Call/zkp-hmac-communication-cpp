#include "base.h"
// Including the header file for the Curve class

Curve::Curve(const std::string &curveName) {
    group = EC_GROUP_new_by_curve_name(OBJ_txt2nid(curveName.c_str()));
    // Creating a new elliptic curve group based on the given curve name
    if (!group) {
        throw std::invalid_argument("Invalid curve name");
    }
    // Checking if the curve creation was successful, throwing an exception if not

    generator = EC_GROUP_get0_generator(group);
    // Getting the generator point of the elliptic curve group
    order = EC_GROUP_get0_order(group);
    // Getting the order of the elliptic curve group
    if (!generator || !order) {
        EC_GROUP_free(group);
        // Freeing the allocated memory for the group if either the generator or order retrieval fails
        throw std::runtime_error("Failed to retrieve curve generator or order");
    }
    // Checking if the generator or order retrieval failed, throwing an exception if so
}

Curve::~Curve() {
    EC_GROUP_free(group);
    // Freeing the allocated memory for the elliptic curve group upon object destruction
}

EC_GROUP *Curve::getGroup() const {
    return group;
    // Returning the elliptic curve group pointer
}

bool Curve::is_on_curve(const EC_POINT *P) const {
    if (!group || !P) {
        throw std::invalid_argument("Invalid group or point");
    }
    // Checking if the group or point is invalid, throwing an exception if so

    EC_KEY *key = EC_KEY_new();
    // Creating a new elliptic curve key structure
    EC_KEY_set_group(key, group);
    // Setting the group for the key
    EC_KEY_set_public_key(key, P);
    // Setting the public key for the key
    int result = EC_POINT_is_on_curve(group, P, nullptr);
    // Checking if the given point lies on the curve
    EC_KEY_free(key);
    // Freeing the allocated memory for the key

    return result == 1;
    // Returning true if the point lies on the curve, otherwise false
}

const EC_POINT *Curve::getGenerator() const {
    return generator;
    // Returning the generator point of the curve
}

const BIGNUM *Curve::getOrder() const {
    return order;
    // Returning the order of the curve
}

int Curve::getDegree() const {
    return EC_GROUP_get_degree(group);
    // Returning the degree of the curve
}
