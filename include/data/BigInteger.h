#ifndef BIGINTEGER_H_INCLUDED
#define BIGINTEGER_H_INCLUDED

#include "ByteArray.h"
#include <deque>

class Random;
namespace NTL {
    class ZZ;
}

/*
 * This is a delegate class for Victor Shoup's
 * Number Theory Library ZZ class.
 */
class BigInteger {

    public:
        static const int LITTLEENDIAN;
        static const int BIGENDIAN;
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
        // prime value.
        BigInteger(int bits, int certainty, Random& rnd);

    private:
        BigInteger(NTL::ZZ *newNumber);

    public:
        BigInteger& operator= (const BigInteger& other);
        BigInteger& operator= (long value);
        /*
        // bool operator== (const BigInteger& other);
        // bool operator!= (const BigInteger& other);
        // bool operator < (const BigInteger& other);
        // bool operator <= (const BigInteger& other);
        // bool operator > (const BigInteger& other);
        // bool operator >= (const BigInteger& other);
        BigInteger operator>> (unsigned shiftCount) const;
        BigInteger operator<< (unsigned shiftCount) const;
*/
    public:
        ~BigInteger();

    public:
        // Returns true if this = other.
        bool equals(const BigInteger& other) const;
        // Returns a BigInteger equal to this mod a.
        BigInteger mod(const BigInteger& a) const;
/*        BigInteger& add(const BigInteger& addend);
        BigInteger absolute() const;
        int bitCount() const; // Returns the number of significant bits.
        int bitSize() const; // Returns the total number of bits
        // Returns the value as an array of unsigned char
        ByteArray byteArray(int endian=BIGENDIAN) const;
        BigInteger& divide(const BigInteger& divisor);
        BigInteger getRemainder() const;
        bool isZero() const;
        bool lessThan(const BigInteger& other) const;
        long longValue() const; // Returns long value. Value returned is truncated
                                // to sizeof(long).
        BigInteger& multiply(const BigInteger& multiplier);
        BigInteger& subtract(const BigInteger& subtrahend);

    private:
        typedef std::deque<unsigned long long> RawBits;
        BigInteger(RawBits& bits, bool sign);   // Used to return the remainder
                                                // or absolute value as a BigInteger.

    private:
        void add(RawBits& a1, const RawBits& a2);
        void borrow(RawBits& sub, unsigned index);
        void carry(unsigned index);
        void clip();
        void diff(RawBits& d1, const RawBits& d2);
        void divide(const RawBits& other);
        bool equals(const RawBits& other) const;
        void leftShift(RawBits& reg, unsigned index=0,
                        unsigned count=1, bool carry=false) const;
        void multiply(const RawBits& other);
        void rightShift(RawBits& reg, unsigned index=0,
                        unsigned count=1) const;
        void zero();
        void zeroRemainder();
*/
    private:
        NTL::ZZ *number;
        
        static const unsigned long long ULLONG_MSB;

};

/*
 * Global operator overloads
*/
bool operator== (const BigInteger& lhs, const BigInteger& rhs);
bool operator!= (const BigInteger& lhs, const BigInteger& rhs);
bool operator< (const BigInteger& lhs, const BigInteger& rhs);
bool operator<= (const BigInteger& lhs, const BigInteger& rhs);
bool operator> (const BigInteger& lhs, const BigInteger& rhs);
bool operator>= (const BigInteger& lhs, const BigInteger& rhs);
BigInteger operator+ (const BigInteger& lhs, const BigInteger& rhs);
BigInteger operator- (const BigInteger& lhs, const BigInteger& rhs);
BigInteger operator* (const BigInteger& lhs, const BigInteger& rhs);
BigInteger operator/ (const BigInteger& lhs, const BigInteger& rhs);
BigInteger operator% (const BigInteger& lhs, const BigInteger& rhs);

#endif // BIGINTEGER_H_INCLUDED
