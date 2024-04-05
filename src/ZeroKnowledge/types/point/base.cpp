#include "base.h"
// Including the header file for the Point class

// Constructor definition for the Point class
Point::Point(EC_POINT *p) : point(p) {}
// Initializing the private member 'point' with the given EC_POINT pointer 'p' in the constructor

// Destructor definition for the Point class
Point::~Point() {
    EC_POINT_free(point);
    // Freeing the memory associated with the EC_POINT object when the Point object is destroyed
}

// Getter function definition to retrieve the EC_POINT pointer
EC_POINT *Point::get() const {
    return point;
    // Returning the stored EC_POINT pointer
}
