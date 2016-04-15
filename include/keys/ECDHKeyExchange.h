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
        Point getPublicKey();
        void setCurve(const CurveParams& params);
        Point getSecret(const Point& fk);

    private:
        ByteArray elementToString(const BigInteger& e, bool galois);
        bool isOnCurve(const Point& point) const;
        Point pointAdd(const Point& a, const Point& b) const;
        Point scalarMultiply(const BigInteger& m,
                                const Point& point) const;

    private:
        bool curveSet;      // Curve parameters set.
        BigInteger n;       // Subgroup order.
        BigInteger A;       // Curve coefficient a;
        BigInteger B;       // Curve coefficient b;
        BigInteger P;       // Curve modulus.
        Point G;            // Base Point.
        Point H;            // Public key.
        BigInteger d;       // Secret key
        Point s;            // Shared secret.

        static Point ZERO;  // 0 infinity point.

};

}

#endif  // ECDHKEYEXCHANGE_H_INCLUDED
