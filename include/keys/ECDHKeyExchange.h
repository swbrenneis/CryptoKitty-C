#ifndef ECDHKEYEXCHANGE_H_INCLUDED
#define ECDHKEYEXCHANGE_H_INCLUDED

#include "data/BigInteger.h"
#include "data/ByteArray.h"

namespace CK {

class ECDHKeyExchange {

    public:
        ECDHKeyExchange();
        ~ECDHKeyExchange();

    private:
        ECDHKeyExchange(const ECDHKeyExchange& other);
        ECDHKeyExchange& operator= (const ECDHKeyExchange& other);

    public:
        struct Point {
            BigInteger x;
            BigInteger y;
        };

        struct CurveParams {
            uint32_t m;     // bitsize
            BigInteger n;   // order
            BigInteger a;   // a coefficient
            BigInteger b;   // b coefficient
            BigInteger xG;  // Base X coordinate
            BigInteger yG;  // Base Y coordinate
            BigInteger p;   // Modulus
            uint32_t h;     // Cofactor
        };

    public:
        ByteArray getPublicKey();
        void setCurve(const CurveParams& params);
        Point getSecret(const Point& fk);

    private:
        ByteArray elementToString(const BigInteger& e) const;
        bool isOnCurve(const Point& point) const;
        Point pointAdd(const Point& P, const Point& Q) const;
        ByteArray pointToString(const Point& point, bool compress);
        Point scalarMultiply(const BigInteger& m,
                                const Point& point) const;

    private:
        bool curveSet;      // Curve parameters set.
        bool galois;        // Finite field flag
        BigInteger n;       // Subgroup order.
        BigInteger a;       // Curve coefficient a;
        BigInteger b;       // Curve coefficient b;
        BigInteger p;       // Curve modulus.
        Point G;            // Base Point.
        Point H;            // Public key.
        BigInteger d;       // Secret key
        Point s;            // Shared secret.
        uint32_t m;         // Galois field size.

        static Point ZERO;  // 0 infinity point.

};

}

#endif  // ECDHKEYEXCHANGE_H_INCLUDED
