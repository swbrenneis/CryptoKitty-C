#ifndef CLIENTKEYEXCHANGE_H_INCLUDED
#define CLIENTKEYEXCHANGE_H_INCLUDED

#include "tls/HandshakeBody.h"
#include "tls/Constants.h"
#include "keys/ECDHKeyExchange.h"
#include "data/BigInteger.h"

namespace CK {
    class RSAPrivateKey;
}

namespace CKTLS {

class ClientKeyExchange : public HandshakeBody {

    public:
        ClientKeyExchange();
        ~ClientKeyExchange();

    private:
        ClientKeyExchange(const ClientKeyExchange& other);
        ClientKeyExchange& operator= (const ClientKeyExchange& other);

    public:
        const CK::ByteArray& encode();
        const CK::BigInteger& getDHPublicKey() const;
        const CK::ByteArray& getECPublicKey() const;
        void initState() {}
        void initState(NamedCurve curve, const CK::ByteArray& pk);
        void initState(const CK::ECDHKeyExchange::CurveParams& p,
                                                const CK::ByteArray& pk);
        void initState(const CK::BigInteger& pk);
        static void setAlgorithm(KeyExchangeAlgorithm alg);

    protected:
        void decode();

    private:
        void decodeDH(const CK::ByteArray& encoded);
        void decodeECDH(const CK::ByteArray& encoded);
        CK::ByteArray encodeDH() const;
        CK::ByteArray encodeECDH() const;

    private:
        static KeyExchangeAlgorithm algorithm;
        // ClientDHParams
        CK::BigInteger dYc;     // D-H public value.
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

#endif  // CLIENTKEYEXCHANGE_H_INCLUDED
