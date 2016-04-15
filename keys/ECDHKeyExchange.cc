#include "keys/ECDHKeyExchange.h"
#include "exceptions/IllegalStateException.h"
#include "exceptions/BadParameterException.h"
#include "random/SecureRandom.h"
#include <cmath>

namespace CK {

// Static initialization.
ECDHKeyExchange::Point ECDHKeyExchange::ZERO =
        { BigInteger::ZERO, BigInteger::ZERO };

ECDHKeyExchange::ECDHKeyExchange()
: curveSet(false),
  galois(false) {

      H.x = H.y = s.x = s.y = BigInteger::ZERO;

}

ECDHKeyExchange::~ECDHKeyExchange() {
}
/*
 * Converts a field element (point coordinate) to an octet string.
 * The conversion depends on whether the curve is defined in terms
 * of a prime modulus or a finite (Galois) field.
 *
 * Certicom Research, SEC 01, v2, section 2.3.5.
 */
ByteArray ECDHKeyExchange::elementToString(const BigInteger& e) const {

    if (!curveSet) {
        throw IllegalStateException("Curve parameters not set");
    }

    ByteArray result;

    if (galois) {
        double mDouble = m;
        int mlen = ceil(mDouble / 8);
        result.setLength(mlen);
        for (int i = 1; i < mlen; ++i) {
            uint8_t octet = 0;
            for (int j = 7; j >= 0; --j) {
                octet = octet << 1;
                if (e.testBit(j + (8 * (mlen - i - 1)))) {
                    octet |= 0x01;
                }
            }
            result[i] = octet;
        }
        uint8_t m0 = 0;
        int bit = m - 1;
        for (uint32_t i = 0; i < 8 - ((8 * mlen) - m); ++i) {
            m0 = m0 << 1;
            if (e.testBit(bit)) {
                m0 |= 0x01;
            }
        }
        result[0] = m0;
    }
    else {
        double pDouble = p.bitLength();
        int mlen = ceil(pDouble / 8);
        ByteArray encoded(e.getEncoded(BigInteger::BIGENDIAN));
        result.setLength(encoded.getLength() - mlen);
        result.append(encoded);
    }

    return result;

}

ByteArray ECDHKeyExchange::getPublicKey() {

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

    return pointToString(H, false);

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
                    - (a * point.x) - b) % p == BigInteger::ZERO;

}

/*
 * Point addition.
 */
ECDHKeyExchange::Point
ECDHKeyExchange::pointAdd(const Point& P, const Point& Q) const {

    BigInteger x1 = P.x;
    BigInteger y1 = P.y;
    BigInteger x2 = Q.x;
    BigInteger y2 = Q.y;

    if (x1 == BigInteger::ZERO && y1 == BigInteger::ZERO) {
        return Q;
    }

    if (x2 == BigInteger::ZERO && y2 == BigInteger::ZERO) {
        return P;
    }

    if (x1 == x2 && y1 != y2) {
        // Point + (-Point) = 0
        return ZERO;
    }

    BigInteger mp;
    if (x1 == x2) {
        // a == b
        BigInteger THREE(3L);
        BigInteger TWO(2L);
        mp = ((THREE * x1.pow(2)) + a) * (TWO * y1).modInverse(p);
    }
    else {
        mp = (y1 - y2) * (x1 - x2).modInverse(p);
    }

    BigInteger x3 = mp.pow(2) - x1 - x2;
    BigInteger y3 = y1 + mp * (x3 - x1);
    Point result;
    result.x = x3 % p;
    result.y = -y3 % p;

    if (!isOnCurve(result)) {   // Something went horribly, horribly wrong.
        throw IllegalStateException("Invalid point addition result");
    }

    return result;

}

/*
 * Convert a curve coordinate to an octet string with or without compression.
 *
 * Certicom Research, SEC 01, v2, section 2.3.3.
 */
ByteArray ECDHKeyExchange::pointToString(const Point& point, bool compress) {

    if (!curveSet) {
        throw IllegalStateException("Curve parameters not set");
    }

    if (point.x == BigInteger::ZERO && point.y == BigInteger::ZERO) {
        return ByteArray(1, 0);
    }

    ByteArray result;
    if (compress) {
        ByteArray x(elementToString(point.x));
        uint8_t yP;
        if (galois) {
            if (point.x == BigInteger::ZERO) {
                yP = 0;
            }
            else {
                BigInteger z = point.y / point.x;
                yP = z.testBit(0) ? 1 : 0;
            }
        }
        else {
            yP = point.y.testBit(0) ? 1 : 0;
        }
        result.setLength(0x02 | yP);
        result.append(x);
    }
    else {
        ByteArray x(elementToString(point.x));
        ByteArray y(elementToString(point.y));
        result.setLength(1, 0x04);
        result.append(x);
        result.append(y);
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
    a = params.a;
    b = params.b;
    p = params.p;
    G.x = params.xG;
    G.y = params.yG;
    m = params.m;

    curveSet = true;

}

}

