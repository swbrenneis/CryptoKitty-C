#ifndef SERVERKEYEXCHANGE_H_INCLUDED
#define SERVERKEYEXCHANGE_H_INCLUDED

#include "tls/HandshakeBody.h"
#include "tls/Constants.h"
#include "keys/ECDHKeyExchange.h"
#include "data/BigInteger.h"

namespace CK {
    class RSAPrivateKey;
}

namespace CKTLS {

class ServerKeyExchange : public HandshakeBody {

    public:
        ServerKeyExchange();
        ~ServerKeyExchange();

    private:
        ServerKeyExchange(const ServerKeyExchange& other);
        ServerKeyExchange& operator= (const ServerKeyExchange& other);

    public:
        void decode(const CK::ByteArray& encoded);
        CK::ByteArray encode() const;
        CK::ECDHKeyExchange::CurveParams getCurve() const;
        const CK::BigInteger& getDHGenerator() const;
        const CK::BigInteger& getDHModulus() const;
        const CK::BigInteger& getDHPublicKey() const;
        const CK::ByteArray& getECPublicKey() const;
        void initState() {}
        void initState(NamedCurve curve, const CK::ByteArray& pk);
        void initState(const CK::ECDHKeyExchange::CurveParams& p,
                                                const CK::ByteArray& pk);
        void initState(const CK::BigInteger& g, const CK::BigInteger& p,
                                                const CK::BigInteger& pk);
        static void setAlgorithm(KeyExchangeAlgorithm alg);

    private:
        void decodeDH(const CK::ByteArray& encoded);
        void decodeECDH(const CK::ByteArray& encoded);
        CK::ByteArray encodeDH() const;
        CK::ByteArray encodeECDH() const;

    private:
        static KeyExchangeAlgorithm algorithm;
        CK::RSAPrivateKey *rsaKey;
        // ServerDHParams
        CK::BigInteger dP;      // D-H prime modulus.
        CK::BigInteger dG;      // D-H generator.
        CK::BigInteger dYs;     // D-H public value.
        CK::ByteArray clientRandom;
        CK::ByteArray serverRandom;
        // EC parameters
        ECCurveType curveType;
        struct ECCurve {
            CK::BigInteger a;
            CK::BigInteger b;
        };
        // Explicit prime curve type
        CK::BigInteger primeP;
        ECCurve curve;
        CK::BigInteger baseX;
        CK::BigInteger baseY;
        CK::BigInteger order;
        uint32_t cofactor;
        // Explicit characteristic 2
        uint16_t m;
        ECBasisType ebType;
        // EC trinomial
        CK::ByteArray k;
        // EC Pentanomial
        CK::ByteArray k1;
        CK::ByteArray k2;
        CK::ByteArray k3;

        // Named curves
        NamedCurve named;
        
        // Key exchange
        CK::ByteArray ecPublicKey;

};

}

#endif  // SERVERKEYEXCHANGE_H_INCLUDED
