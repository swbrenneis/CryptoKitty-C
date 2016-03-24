#include "data/BigInteger.h"
#include "data/OutOfRangeException.h"
#include "random/Random.h"
#include <algorithm>
#include <climits>
#include "NTL/ZZ.h"

namespace CK {

/*
 * Static initialization
 */
const BigInteger BigInteger::ZERO;
const BigInteger BigInteger::ONE(1);
const unsigned long long
    BigInteger::ULLONG_MSB = (ULLONG_MAX >> 1) ^ ULLONG_MAX;
// const int BigInteger::LITTLEENDIAN = 1;
// const int BigInteger::BIGENDIAN = 2;

/* Uses small coprime test, 64 rounds of Miller-Rabin, and
 * tests for Germain primality, if indicated.
 */ 
void makePrime(NTL::ZZ& n, bool sgPrime) {

    bool provisional = false;
    // Improve Miller-Rabin probability.
    long smallPrimes[] = { 3, 5, 7, 11, 13, 17, 19 };
    while (!provisional) {
        provisional = true;
        for (int i = 0; i < 7 && provisional; ++i) {
            provisional = NTL::GCD(n, NTL::ZZ(smallPrimes[i])) == 1;
        }
        if (!provisional) {
            n += 2;
        }
    }
    // I don't think Shoup knows that there is a bool type
    // in C++.
    provisional = false;
    while (!provisional) {
        provisional = NTL::ProbPrime(n, 64) == 1;
        if (!provisional) {
            n += 2;
        }
    }

    // We'll just use Miller-Rabin for the Germain prime.
    if (sgPrime) {
        provisional = false;
        while (!provisional) {
            provisional = NTL::ProbPrime((n * 2) + 1, 64) == 1;
            if (!provisional) {
                n += 2;
                makePrime(n, true);
            }
        }
    }

}

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
 * Construct a BigInteger that is a probabilistic random
 * prime, with the specified length. The prime is tested
 * with 64 Miller-Rabin rounds after some small prime
 * tests. The prime will also be a Sophie Germain prime
 * if the boolean is true (p and 2p+2 both prime). Selecting
 * Germain primes is very time-consuming.
 */
BigInteger::BigInteger(int bits, bool sgPrime, Random& rnd) {

    ByteArray pBytes(bits/8 + ((bits % 8 != 0) ? 1 : 0));
    rnd.nextBytes(pBytes);
    // We're going to do everything in bigendian order.
    // Make sure it is at least bits - (bits mod 8) significant.
    while (pBytes[0] == 0) {
        rnd.nextBytes(pBytes);
    }

    // Load the big integer.
    NTL::ZZ work(pBytes[0]);
    for (unsigned n = 1; n < pBytes.length(); ++n) {
        work = work << 8;
        work = work | pBytes[1];
    }

    // Make sure it's positive.
    if (work < 0) {
        work = abs(work);
    }

    // Make sure it's odd.
    if (work % 2 == 0) {
        work++;
    }

    makePrime(work, sgPrime);
    number = new NTL::ZZ(work);

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
 * Returns the position of the most significant bit that is
 * different than the sign bit.
 */
int BigInteger::bitLength() const {

    return NTL::NumBits(*number);

}

/*
 * Returns true if this = other.
 */
bool BigInteger::equals(const BigInteger& other) const {

    return NTL::compare(*number, *other.number) == 0;

}

/*
 * Returns the greatest common denominator of this and a.
 */
BigInteger BigInteger::gcd(const BigInteger& a) const {

    return BigInteger(new NTL::ZZ(NTL::GCD(*number, *a.number)));

}

/*
 * Returns a BigInteger object that is the remainder of this divided by a.
 */
BigInteger BigInteger::mod(const BigInteger& a) const {

    return BigInteger(new NTL::ZZ(*number % *a.number));

}

/*
 * Returns a BigInteger that is equal to (this**exp) % m.
 */
BigInteger BigInteger::modPow(const BigInteger& exp, const BigInteger& m) {

    return BigInteger(new NTL::ZZ(
                            NTL::PowerMod(*number, *exp.number, *m.number)));

}

/*
 * Returns a BigInteger that is the product of this and multiplier.
 */
BigInteger BigInteger::multiply(const BigInteger& multiplier) const {

    return BigInteger(new NTL::ZZ((*number) * (*multiplier.number)));

}

/*
 * Send the value to a standard output stream.
 */
void BigInteger::out(std::ostream& o) const {

    o << *number;

}

/*
 * Returns a BigInteger that is this shifted right count times.
 */
BigInteger BigInteger::rightShift(long count) const {

    return BigInteger(new NTL::ZZ(*number >> count));

}

/*
 * Returns true if the specified bit is set.
 */
bool BigInteger::testBit(int bitnum) const {

    return NTL::bit(*number, bitnum) == 1;

}

}

// Global operators
bool operator== (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return lhs.equals(rhs); }
bool operator!= (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return !lhs.equals(rhs); }
CK::BigInteger operator% (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return lhs.mod(rhs); }
CK::BigInteger operator* (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return lhs.multiply(rhs); }
CK::BigInteger operator>> (const CK::BigInteger& lhs, long rhs)
{ return lhs.rightShift(rhs); }
std::ostream& operator<< (std::ostream& out, const CK::BigInteger& bi)
{ bi.out(out); return out; }
