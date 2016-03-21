#include "data/BigInteger.h"
#include "data/OutOfRangeException.h"
#include <algorithm>
#include <climits>
#include "NTL/ZZ.h"

/*
 * Static initialization
 */
const BigInteger BigInteger::ZERO;
const BigInteger BigInteger::ONE(1);
const unsigned long long
    BigInteger::ULLONG_MSB = (ULLONG_MAX >> 1) ^ ULLONG_MAX;
const int BigInteger::LITTLEENDIAN = 1;
const int BigInteger::BIGENDIAN = 2;

/*
 * Default constructor
 * Sets value to 0
 */
BigInteger::BigInteger()
: number(new NTL::ZZ(0)){
}

/*
 * Copy constructor
 */
BigInteger::BigInteger(const BigInteger& other)
: number(new NTL::ZZ(*other.number)) {
}

/*
 * Constructor with initial long long value
 */
BigInteger::BigInteger(long initial)
: number(new NTL::ZZ(initial)) {
}

/*
 * Construct a BigInteger from a byte array
 */
BigInteger::BigInteger(const ByteArray& bytes) {
}

/*
 * Construct a BigInteger with a new NTL integer.
 */
BigInteger::BigInteger(NTL::ZZ *newNumber)
: number(newNumber) {
}

/*
 * Destructor
 */
BigInteger::~BigInteger() {

    delete number;

}

/*
 * Assignment operator
 */
BigInteger& BigInteger::operator= (const BigInteger& other) {

    delete number;
    number = new NTL::ZZ(*other.number);
    return *this;

}

/*
 * Assignment operator
 */
BigInteger& BigInteger::operator= (long value) {

    delete number;
    number = new NTL::ZZ(value);
    return *this;

}

/*
 * Returns true if this = other.
 */
bool BigInteger::equals(const BigInteger& other) const {

    return NTL::compare(*number, *other.number) == 0;

}

/*
 * Returns a BigInteger object that is the remainder of this divided by a.
 */
BigInteger BigInteger::mod(const BigInteger& a) const {


    return BigInteger(new NTL::ZZ(*number % *a.number));

}

// Global operators
bool operator== (const BigInteger& lhs, const BigInteger& rhs)
{ return lhs.equals(rhs); }
bool operator!= (const BigInteger& lhs, const BigInteger& rhs)
{ return !lhs.equals(rhs); }
BigInteger operator% (const BigInteger& lhs, const BigInteger& rhs)
{ return lhs.mod(rhs); }

