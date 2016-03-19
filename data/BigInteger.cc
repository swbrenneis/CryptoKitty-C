#include "../include/data/BigInteger.h"
#include "../include/data/OutOfRangeException.h"
#include <algorithm>
#include <climits>

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
BigInteger::BigInteger() {

    zero();

}

/*
 * Copy constructor
 */
BigInteger::BigInteger(const BigInteger& other)
: number(other.number),
  sign(other.sign),
  remainder(other.remainder),
  remainderSign(other.remainderSign) {
}

/*
 * Constructor with initial long long value
 */
BigInteger::BigInteger(long long initial) {

    zeroRemainder();
    sign = initial >= 0;
    number.push_back(std::abs(initial));

}

/*
 * Construct a BigInteger from a byte array
 */
BigInteger::BigInteger(const ByteArray& bytes)
: sign(true) {

    zeroRemainder();
    unsigned biSize = bytes.length() / sizeof(unsigned long long);
    if (bytes.length() % sizeof(unsigned long long) != 0) {
        biSize++;
    }
    number.resize(biSize, 0);
    unsigned bitCount = bytes.length() * 8;
    unsigned char mask = 0x80;
    unsigned index = 0;
    unsigned char byte = bytes[index];
    while (bitCount > 0) {
        if ((byte & mask) != 0) {
            leftShift(number, 0, 1, true);
        }
        else {
            leftShift(number, 0, 1, false);
        }
        bitCount--;
        byte = byte << 1;
        if (bitCount % 8 == 0) {
            index++;
            byte = bytes[index];
        }
    }
    clip();

}

/*
 * Destructor
 */
BigInteger::~BigInteger() {
}

/*
 * Assignment operator
 */
BigInteger& BigInteger::operator= (const BigInteger& other) {

    number = other.number;
    sign = other.sign;
    remainder = other.remainder;
    remainderSign = other.remainderSign;
    return *this;

}

/*
 * Right shift operator. A logical right shift is performed
 * on the number array of a copy of this BigInteger.
 */
BigInteger BigInteger::operator>> (unsigned count) const {

    BigInteger result(*this);
    rightShift(result.number, 0, count);
    return result;

}

/*
 * Left shift operator. A logical left shift is performed
 * on the number array of a copy of this BigInteger.
 */
BigInteger BigInteger::operator<< (unsigned count) const {

    BigInteger result(*this);
    leftShift(result.number, 0, count, false);
    return result;

}

/*
 * Unary addition operator.
 * Binary operator will be gobal. See BigInteger.h
 */
BigInteger& BigInteger::add(const BigInteger& other) {

    zeroRemainder();
    if (isZero()) {
        *this = other;
    }
    else if (other.isZero()) { /* Do nothing */ }
    else if (sign == other.sign) { // Signs the same. Absolute sum.
        add(number, other.number);
    }
    else {
        if (other.number > number) {    // Larger value retains sign
            sign = other.sign;
        }
        diff(number, other.number); // Absolute difference
    }

    return *this;

}

/*
 * Add with carry. Places the result in a1.
 * It is assumed that zero checks have been done
 * by the calling function.
 */
void BigInteger::add(RawBits& a1, const RawBits& a2) {

    RawBits result;

    unsigned size = std::max(a1.size(), a2.size());
    result.resize(size, 0);

    unsigned long long a = 0;
    unsigned long long b = 0;
    for (unsigned n = 0; n < size; n++) {    // Sum all of the bits
        a = a1[n];
        b = a2[n];
        result[n] = a + b;
        if (result[n] < a || result[n] < b) { // Overflow. Need to carry.
            carry(n + 1);
        }
    }
    a1 = result;

}

/*
 * Returns the number of significant bits in the value.
 *
 * A binary value of 0010001110100010 will return 14.
 */
int BigInteger::bitCount() const {    // FIX ME: Why can't this be const?

    int bitcount = bitSize();
    RawBits temp = number;
    while ((temp[temp.size()-1] & ULLONG_MSB) == 0) {
        leftShift(temp);
        bitcount--;
    }
    return bitcount;

}

/*
 * Return the total number of bits in the number array.
 *
 * A binary value of 0010001110100010 will return 16.
 */
int BigInteger::bitSize() const {

    return number.size() * sizeof(unsigned long long) * 8;

}

/*
 * Recursive borrow.
 * This is called from the diff function, so it has already been
 * determined that sub has enough eventual bits for the borrow.
 * If the bit block is 0, the it is set to ULLONG_MAX and the
 * function recurses to borrow again.
 */
void BigInteger::borrow(RawBits& sub, unsigned index) {

    if (sub[index] == 0) {
        sub[index] = ULLONG_MAX;
        borrow(sub, index+1);
    }
    else {
        sub[index]--;
    }

}

/*
 * Output the value of the integer in a byte array.
 * little endian = 1, big endian = 2;
 */
ByteArray BigInteger::byteArray(int endian) const {

    ByteArray result;
    unsigned byteLength = number.size() * sizeof(unsigned long long);
    result.setLength(byteLength);
    int bits = bitSize();
    unsigned index;
    switch (endian) {
        case LITTLEENDIAN:
            index = 0;
            break;
        case BIGENDIAN:
            index = byteLength - 1;
            break;
        default:
            throw OutOfRangeException("Illegal endian value.");
    }
    unsigned char byte = 0;
    RawBits theNumber(number);
    for (int n = 1; n <= bits; ++n) {
        if ((theNumber[0] & 1) != 0) {
            byte |= 0x80;
        }
        if (n % 8 == 0) {
            result[index] = byte;
            byte = 0;
            switch (endian) {
                case LITTLEENDIAN:
                    index++;
                    break;
                case BIGENDIAN:
                    index--;
                    break;
            }
        }
        byte = byte >> 1;
        rightShift(theNumber);
    }
    return result;
            
}

/*
 * Recursive carry function.
 */
void BigInteger::carry(unsigned index) {

    if (index < number.size()) {
        number[index]++;
        if (number[index] == 0) {   // Overflow
            carry(index + 1);
        }
    }
    else {
        number.push_back(1);
    }

}

/*
 * Removes leading zeroes.
 */
void BigInteger::clip() {

    while (number.back() == 0) {
        number.pop_back();
    }

}

/*
 * Unsigned difference function. Iteratively subtracts bit blocks
 * with borrowing. The zero and equals checks are assumed to have
 * been done in the calling function.
 */
void BigInteger::diff(RawBits& d1, const RawBits& d2) {

    RawBits bigger(d2 > d1 ? d2 : d1);
    RawBits smaller(d2 < d1 ? d2 : d1);
    d1.resize(1, 0);    // Zero d1 for result.
    unsigned long long subtrahend, bump;
    for (unsigned n = 0; n < bigger.size(); n++) {
        subtrahend = bigger[n];
        bump = 0;
        if (smaller[n] > subtrahend) {
            /* Need to borrow. Magic happens here.
               We don't have an extra MSB to set for the borrow
               so we have to improvise. The subtrahend is set
               to ULLONG_MAX and subtraction is performed. Since
               we have really subtracted one less than the borrow,
               we have to add the subtrahend + 1 back in. */
            bump = subtrahend + 1;
            borrow(bigger, n);
            subtrahend = ULLONG_MAX;
        }
        d1[n] = (subtrahend - smaller[n]) + bump;
    }
    clip();

}

/*
 * Unary division operator with remainder.
 * Binary operator will be gobal. See BigInteger.h
 */
BigInteger& BigInteger::divide(const BigInteger& other) {

    zeroRemainder();
    if (other.isZero()) {
        throw DivideByZeroException();
    }
    else if (isZero()) { /* Do nothing */ }
    else if (other > *this) {
        zero();
        remainder = other.number;
        remainderSign = other.sign;
    }
    else {
        divide(other.number);
        sign = sign == other.sign;
    }
    return *this;

}

/*
 * Divide with remainder. The result will be placed in number and
 * the remainder will be placed in remainder
 */
void BigInteger::divide(const RawBits& other) {

    zeroRemainder();
    RawBits quotient;
    RawBits dividend;
    int bitcount = bitSize();
    unsigned long long& msw = number[number.size()-1];

    while ((msw & 1) == 0) {
        bitcount--;
        leftShift(number);
    }
    dividend.resize(1, 1);  // dividend = 1;
    while (bitcount > 0) {
        if (other <= dividend) {
            leftShift(quotient, 0, 1, true);
            diff(dividend, other);
        }
        else {
            leftShift(quotient);
        }
        leftShift(number);
        // Shift in MSB from number.
        leftShift(dividend, 0, 1, (msw & ULLONG_MSB) != 0);
        bitcount--;
    }
    number = quotient;
    remainder = dividend;

}

/*
 * Test to see of other RawBits deque holds the same value as number.
 */
bool BigInteger::equals(const BigInteger& other) const {

    return equals(other.number);

}
 
/*
 * Test to see of other RawBits deque holds the same value as number.
 */
bool BigInteger::equals(const RawBits& other) const {

    if (number.size() != other.size()) {
        return false;
    }

    RawBits::const_iterator nIter = number.begin();
    RawBits::const_iterator oIter = other.begin();
    while (oIter != other.end()) {
        if (*oIter != *nIter) {
            return false;
        }
        oIter++;
        nIter++;
    }
    return true;

}
 
/*
 * Test for zero.
 */
bool BigInteger::isZero() const {

    return number.size() == 1 && number[0] == 0;

}

/*
 * Recursive logical left shift
 */
void BigInteger::leftShift(RawBits& reg, unsigned index,
                            unsigned count, bool carry) const {

    bool nextCarry = (reg[index] & ULLONG_MSB) != 0;
    reg[index] = reg[index] << 1;
    if (carry) {
        reg[index] |= 1;
    }
    if (index < reg.size()) {   // Recurse to finish all blocks
        leftShift(reg, index+1, 1, nextCarry);
    }
    if (count > 1) {    // Recurse to satisfy count
        leftShift(reg, 0, count-1, false);
    }

}

/*
 * Signed value comparison.
 */
bool BigInteger::lessThan(const BigInteger& other) const {

    if (number == other.number) {
        return false;
    }
    // Sign checks
    if (sign == other.sign) {   // Same sign.
        if (sign) { // Both positive.
            return number < other.number;
        }
        else {  // Both negative.
            return number > other.number;
        }
    }
    else {
        if (sign) { // other is negative
            return false;
        }
        else {  // This is negative, Other is positive.
            return true;
        }
    }

}

/*
 * Return the integer as a signed long value. If the absolute value
 * is larger than ULONG_MAX, it will be truncated.
 */
long BigInteger::longValue() const {

    long result = number[0] & ULONG_MAX;
    if (!sign) {
        result = 0 - result;
    }
    return result;

}

/*
 * Unary multiplication operator.
 * Binary operator will be gobal. See BigInteger.h
 */
BigInteger& BigInteger::multiply(const BigInteger& other) {

    zeroRemainder();
    if (other.isZero() || isZero()) {
        zero(); // Yes, doing this might be redundant.
    }
    else if (other == BigInteger::ONE) { /* Do nothing */ }
    else if (*this == BigInteger::ONE) {
        *this = other;
    }
    else {
        multiply(other.number);
        if (!other.sign && !sign) { // Adjust sign
            sign = true;
        }
        else if (!other.sign) {
            sign = false;
        }
    }
    return *this;

}
 
/*
 * Unsigned multiply. It is assumed that all zero checks and
 * sign adjustment are done by the calling function.
 * Multiplies by right shifting
 */
void BigInteger::multiply(const RawBits& other) {

    RawBits multiplier(other);
    unsigned shiftCount = 0;
    unsigned multBitCount =
            other.size() * sizeof(unsigned long long) * 8;
    RawBits product;
    product.resize(1, 0);
    RawBits sum;
    sum.resize(1, 0);
    if ((multiplier[0] & 1) != 0) {
        product = sum = number;
    }

    for (unsigned n = 1; n < multBitCount; ++n) {
        shiftCount++;
        rightShift(multiplier);
        if ((multiplier[0] & 1) != 0) {
            leftShift(product, 0, shiftCount);
            add(sum, product);
            shiftCount = 0;
        }
    }
    number = sum;

}

/*
 * Recursive logical right shift.
 */
void BigInteger::rightShift(RawBits& reg, unsigned index, unsigned count) const {

    reg[index] = reg[index] >> 1;
    unsigned next = index + 1;
    if (next < reg.size()) {
        if ((reg[next] & 1) != 0) {
            reg[index] |= ULLONG_MSB;
        }
        rightShift(reg, next, 1);   // Recurse to finish all blocks
    }
    if (count > 1) {    // Recurse to satisfy count
        rightShift(reg, 0, count - 1);
    }

}

/*
 * Unary subtraction operator.
 * Binary operator will be gobal. See BigInteger.h
 */
BigInteger& BigInteger::subtract(const BigInteger& other) {

    zeroRemainder();
    if (other.isZero()) { /* Do nothing */ }
    else if (*this == other) {   // Values equal, answer is zero.
        zero();
    }
    else if (sign == other.sign) {   // Signs same, subtract
        diff(number, other.number);
        if (other.number > number) {    // Change sign
            sign = !sign;
        }
    }
    else {  // Absolute sum, gets my sign.
        add(number, other.number);
    }
    return *this;

}

/*
 * Zero the integer value.
 */
void BigInteger::zero() {

    zeroRemainder();
    number.resize(1, 0);
    sign = true;

}

/*
 * Zero the remainder.
 */
void BigInteger::zeroRemainder() {

    remainder.resize(1, 0);
    remainderSign = true;

}

// Global operator overloads
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
{ BigInteger result(lhs); result.add(rhs); return result; }

BigInteger operator- (const BigInteger& lhs, const BigInteger& rhs)
{ BigInteger result(lhs); result.subtract(rhs); return result; }

BigInteger operator* (const BigInteger& lhs, const BigInteger& rhs)
{ BigInteger result(lhs); result.multiply(rhs); return result; }

BigInteger operator/ (const BigInteger& lhs, const BigInteger& rhs)
{ BigInteger result(lhs); result.divide(rhs); return result; }
