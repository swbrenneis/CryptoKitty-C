#ifndef BIGINTEGER_H_INCLUDED
#define BIGINTEGER_H_INCLUDED

#include "ByteArray.h"
#include <deque>
#include <iostream>

namespace NTL {
    class ZZ;
}

namespace CK {

class Random;

/*
 * This is a delegate class for Victor Shoup's
 * Number Theory Library ZZ class.
 */
class BigInteger {

    public:
        // static const int LITTLEENDIAN;
        // static const int BIGENDIAN;
        static const BigInteger ZERO;
        static const BigInteger ONE;

    public:
        class DivideByZeroException {
            public:
                DivideByZeroException() {}
                ~DivideByZeroException() {}
        };

    public:
        // Constructs a BigInteger object with a value of 0 
        BigInteger();
        BigInteger(const BigInteger& other);
        BigInteger(const ByteArray& bytes);
        // Constructs a BigInteger object with initial value
        BigInteger(long intial);
        // Constructs a BigInteger object with a probablistic
        // prime value. If sgPrime = true, the number will be
        // a safe prime.
        BigInteger(int bits, bool sgPrime, Random& rnd);

    private:
        BigInteger(NTL::ZZ *newNumber);

    public:
        BigInteger& operator= (const BigInteger& other);
        BigInteger& operator= (long value);

    public:
        ~BigInteger();

    public:
        // Returns the number of significant bits.
        int bitLength() const;
        // Returns the total number of bits
        int bitSize() const;
        // Returns true if this = other.
        bool equals(const BigInteger& other) const;
        // Returns the greatest common denominator of this and a.
        BigInteger gcd(const BigInteger& a) const;
        // Returns a BigInteger equal to this mod a.
        BigInteger mod(const BigInteger& a) const;
        // Returns the modular inverse. x = a^{-1} mod n. Throws a
        // Data exception if a = 0 or if a and n are not coprime.
        BigInteger modInverse(const BigInteger& n);
        // Returns BigInteger equal to this**exp mod m.
        BigInteger modPow(const BigInteger& exp, const BigInteger& m);
        // Returns a BigInteger equal to this * multiplier.
        BigInteger multiply(const BigInteger& multiplier) const;
        // Returns a BigInteger equal to this shifted right count times.
        BigInteger rightShift(long count) const;
        // Returns true if the specified bit is set.
        bool testBit(int bitnum) const;

    public:
        void out(std::ostream& o) const;

    private:
        NTL::ZZ *number;
        
        static const unsigned long long ULLONG_MSB;

};

}

/*
 * Global operator overloads
*/
bool operator== (const CK::BigInteger& lhs, const CK::BigInteger& rhs);
bool operator!= (const CK::BigInteger& lhs, const CK::BigInteger& rhs);
bool operator< (const CK::BigInteger& lhs, const CK::BigInteger& rhs);
bool operator<= (const CK::BigInteger& lhs, const CK::BigInteger& rhs);
bool operator> (const CK::BigInteger& lhs, const CK::BigInteger& rhs);
bool operator>= (const CK::BigInteger& lhs, const CK::BigInteger& rhs);
CK::BigInteger operator+ (const CK::BigInteger& lhs, const CK::BigInteger& rhs);
CK::BigInteger operator- (const CK::BigInteger& lhs, const CK::BigInteger& rhs);
CK::BigInteger operator* (const CK::BigInteger& lhs, const CK::BigInteger& rhs);
CK::BigInteger operator/ (const CK::BigInteger& lhs, const CK::BigInteger& rhs);
CK::BigInteger operator% (const CK::BigInteger& lhs, const CK::BigInteger& rhs);
CK::BigInteger operator>> (const CK::BigInteger& lhs, long rhs);
CK::BigInteger operator<< (const CK::BigInteger& lhs, long rhs);
std::ostream& operator<< (std::ostream& out, const CK::BigInteger& bi);

#endif // BIGINTEGER_H_INCLUDED
