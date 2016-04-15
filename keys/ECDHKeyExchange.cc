#include "keys/ECDHKeyExchange.h"
#include "exceptions/IllegalStateException.h"
#include "exceptions/BadParameterException.h"
#include "random/SecureRandom.h"

namespace CK {

// Static initialization.
ECDHKeyExchange::Point ECDHKeyExchange::ZERO =
        { BigInteger::ZERO, BigInteger::ZERO };

ECDHKeyExchange::ECDHKeyExchange()
: curveSet(false) {

      H.x = H.y = s.x = s.y = BigInteger::ZERO;

}

ECDHKeyExchange::~ECDHKeyExchange() {
}
/*
 * Converts a field element (point coordinate) to an
 * octet string. The conversion depends on whether the
 * curve is defined in terms of a prime modulus or a
 * finite (Galois) field.
 *
 * Certicom Research, SEC 01, v2, section 2.3.5.
 */
ByteArray ECDHKeyExchange::elementToString(const BigInteger& e, bool galois) {

    ByteArray result;

    if (galois) {
    }
    else {
    }

    return result;

}

ECDHKeyExchange::Point ECDHKeyExchange::getPublicKey() {

    if (!curveSet) {
        throw IllegalStateException("Curve parameters not set");
    }

    if (H.x == BigInteger::ZERO) {
        SecureRandom *rnd = SecureRandom::getSecureRandom("BBS");
        BigInteger n1 = n - BigInteger::ONE;
        d = BigInteger(n.bitLength(), true, *rnd);
        while (d >= n1) {
            d = BigInteger(n.bitLength(), true, *rnd);
        }
        delete rnd;
        H = scalarMultiply(d, G);
    }

    return H;

}

/*
 * Returns the shared secret. Computes it if it hasn't been
 * done.
 */
ECDHKeyExchange::Point ECDHKeyExchange::getSecret(const Point& fk) {

    if (!curveSet) {
        throw IllegalStateException("Curve parameters not set");
    }

    if (!isOnCurve(fk)) {
        throw BadParameterException("Invalid foreign public key");
    }

    if (s.x == BigInteger::ZERO) {
        s = scalarMultiply(d, fk);
    }

    return s;

}

bool ECDHKeyExchange::isOnCurve(const Point& point) const {

    if (!curveSet) {
        throw IllegalStateException("Curve parameters not set");
    }

    return (point.y.pow(2) - point.x.pow(3)
                    - (A * point.x) - B) % P == BigInteger::ZERO;

}

/*
 * Point addition.
 */
ECDHKeyExchange::Point
ECDHKeyExchange::pointAdd(const Point& a, const Point& b) const {

    BigInteger x1 = a.x;
    BigInteger y1 = a.y;
    BigInteger x2 = b.x;
    BigInteger y2 = b.y;

    if (x1 == BigInteger::ZERO && y1 == BigInteger::ZERO) {
        return b;
    }

    if (x2 == BigInteger::ZERO && y2 == BigInteger::ZERO) {
        return a;
    }

    if (x1 == x2 && y1 != y2) {
        // Point + (-Point) = 0
        return ZERO;
    }

    BigInteger m;
    if (x1 == x2) {
        // a == b
        BigInteger THREE(3L);
        BigInteger TWO(2L);
        m = ((THREE * x1.pow(2)) + A) * (TWO * y1).modInverse(P);
    }
    else {
        m = (y1 - y2) * (x1 - x2).modInverse(P);
    }

    BigInteger x3 = m.pow(2) - x1 - x2;
    BigInteger y3 = y1 + m * (x3 - x1);
    Point result;
    result.x = x3 % P;
    result.y = -y3 % P;

    if (!isOnCurve(result)) {   // Something went horribly, horribly wrong.
        throw IllegalStateException("Invalid point addition result");
    }

    return result;

}

/*
 * Multiplication by double and add. There is probably a better way.
 */
ECDHKeyExchange::Point
ECDHKeyExchange::scalarMultiply(const BigInteger& m, const Point& point) const {

    Point result;
    Point a(point);
    BigInteger k(m);

    while (k != BigInteger::ZERO) {
        if (k.testBit(0)) {
            result = pointAdd(result, a);
        }
        // Double
        a = pointAdd(a, a);
        k = k >> 1;
    }

    if (!isOnCurve(result)) {   // Something went horribly, horribly wrong.
        throw IllegalStateException("Invalid scalar multiplication result");
    }

    return result;

}

/*
 * Set the curve parameters.
 */
void ECDHKeyExchange::setCurve(const CurveParams& params) {

    n = params.n;
    A = params.a;
    B = params.b;
    P = params.p;
    G.x = params.xG;
    G.y = params.yG;

    curveSet = true;

}

}

