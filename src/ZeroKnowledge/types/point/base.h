#ifndef ZEROKNOWLEDGE_TYPES_POINT_BASE_H
// Preprocessor directive to ensure that this header file is included only once during compilation

#define ZEROKNOWLEDGE_TYPES_POINT_BASE_H
// Definition of the header guard macro to prevent multiple inclusions of the header file

#include <openssl/ec.h>
// Including the OpenSSL library header file for elliptic curve operations

// Declaration of the Point class
class Point {
// Declaration of a class named Point
private:
    EC_POINT *point;
    // Declaration of a pointer to an elliptic curve point structure as a private member

public:
    // Constructor to initialize the Point object with an EC_POINT pointer
    Point(EC_POINT *p);
    // Declaration of the constructor for the Point class, which takes an EC_POINT pointer as a parameter

    // Destructor to release resources associated with the Point object
    ~Point();
    // Declaration of the destructor for the Point class

    // Getter function to retrieve the EC_POINT pointer
    EC_POINT *get() const;
    // Declaration of a method to get the EC_POINT pointer
};

#endif // ZEROKNOWLEDGE_TYPES_POINT_BASE_H
// End of the header guard macro definition and the end of the header file
