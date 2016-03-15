#ifndef BIGINTEGER_H_INCLUDED
#define BIGINTEGER_H_INCLUDED

#include <deque>

class BigInteger {

    public:
        class DivideByZeroException {
            public:
                DivideByZeroException() {}
                ~DivideByZeroException() {}
        };

    public:
        static const BigInteger ZERO;
        static const BigInteger ONE;

    public:
        BigInteger(); // Creates BigInteger instance with a value of 0
        BigInteger(const BigInteger& other);
        BigInteger(long long intial);   // Creates BigInteger with initial value

    public:
        BigInteger& operator= (const BigInteger& other);
        BigInteger& operator= (const unsigned long long value);
        // bool operator== (const BigInteger& other);
        // bool operator!= (const BigInteger& other);
        // bool operator < (const BigInteger& other);
        // bool operator <= (const BigInteger& other);
        // bool operator > (const BigInteger& other);
        // bool operator >= (const BigInteger& other);
        BigInteger& operator+ (const BigInteger& addend);
        BigInteger& operator- (const BigInteger& subtrahend);
        BigInteger& operator* (const BigInteger& subtrahend);
        BigInteger& operator/ (const BigInteger& subtrahend);

    public:
        ~BigInteger();

    public:
        BigInteger absolute() const;
        int bitCount() const; // Returns the number of significant bits.
        int bitSize() const; // Returns the total number of bits
        bool equals(const BigInteger& other) const;
        BigInteger getRemainder() const;
        bool lessThan(const BigInteger& other) const;
        bool isZero() const;

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

    private:
        RawBits number; // Absolute value of the integer
        bool sign;  // true = positive or zero
        RawBits remainder;   // Remainser, if any, from division
        bool remainderSign;

        static const unsigned long long ULLONG_MSB;

};

/*
 * Global operator overloads
*/
bool operator== (const BigInteger& lhs, const BigInteger& rhs)
{ return lhs.equals(rhs); }

bool operator!= (const BigInteger& lhs, const BigInteger& rhs)
{ return !lhs.equals(rhs); }

bool operator< (const BigInteger& lhs, const BigInteger& rhs)
{ return lhs.lessThan(rhs); }

bool operator<= (const BigInteger& lhs, const BigInteger& rhs)
{ return lhs.lessThan(rhs) || lhs.equals(rhs); }

bool operator> (const BigInteger& lhs, const BigInteger& rhs)
{ return !(lhs <= rhs); }

bool operator>= (const BigInteger& lhs, const BigInteger& rhs)
{ return lhs > rhs || lhs.equals(rhs); }

BigInteger operator+ (const BigInteger& lhs, const BigInteger& rhs)
{ BigInteger result = lhs + rhs; return result; }

BigInteger operator- (const BigInteger& lhs, const BigInteger& rhs)
{ BigInteger result = lhs - rhs; return result; }

BigInteger operator* (const BigInteger& lhs, const BigInteger& rhs)
{ BigInteger result = lhs * rhs; return result; }

BigInteger operator/ (const BigInteger& lhs, const BigInteger& rhs)
{ BigInteger result = lhs / rhs; return result; }

#endif // BIGINTEGER_H_INCLUDED
