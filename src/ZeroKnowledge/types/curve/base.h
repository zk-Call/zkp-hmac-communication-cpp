#ifndef ZEROKNOWLEDGE_TYPES_CURVE_BASE_H
// Preprocessor directive to ensure that this header file is included only once during compilation

#define ZEROKNOWLEDGE_TYPES_CURVE_BASE_H
// Definition of the header guard macro to prevent multiple inclusions of the header file

#include <openssl/ec.h>
// Including the OpenSSL library header file for elliptic curve operations

#include <openssl/obj_mac.h>
// Including the OpenSSL library header file for object definitions

#include <iostream>
// Including the standard input/output stream library for console I/O operations

#include <openssl/objects.h>
// Including the OpenSSL library header file for object-related operations

class Curve {
// Declaration of a class named Curve
private:
    EC_GROUP *group;
    // Declaration of a pointer to an elliptic curve group structure
    const EC_POINT *generator;
    // Declaration of a pointer to a constant elliptic curve point structure representing the generator point
    const BIGNUM *order;
    // Declaration of a pointer to a constant BIGNUM structure representing the order of the elliptic curve group

public:
    Curve(const std::string &curveName);
    // Declaration of the constructor for the Curve class, which takes a reference to a constant string as a parameter
    ~Curve();
    // Declaration of the destructor for the Curve class
    EC_GROUP *getGroup() const;
    // Declaration of a method to get the elliptic curve group
    bool is_on_curve(const EC_POINT *P) const;
    // Declaration of a method to check if a given point lies on the curve
    const EC_POINT *getGenerator() const;
    // Declaration of a method to get the generator point of the curve
    const BIGNUM *getOrder() const;
    // Declaration of a method to get the order of the curve
    int getDegree() const;
    // Declaration of a method to get the degree of the curve
    // Add other necessary methods
};

#endif // ZEROKNOWLEDGE_TYPES_CURVE_BASE_H
// End of the header guard macro definition and the end of the header file
