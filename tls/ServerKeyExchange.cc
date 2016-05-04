#include "tls/ServerKeyExchange.h"
#include "tls/ConnectionState.h"
#include "tls/ServerCertificate.h"
#include "cipher/PKCS1rsassa.h"
#include "keys/RSAPrivateKey.h"
#include "data/Unsigned16.h"
#include "data/Unsigned32.h"
#include "digest/SHA256.h"
#include "digest/SHA384.h"
#include "digest/SHA512.h"
#include "exceptions/tls/RecordException.h"
#include "exceptions/tls/EncodingException.h"

namespace CKTLS {

// Static initilization.
KeyExchangeAlgorithm ServerKeyExchange::algorithm;

ServerKeyExchange::ServerKeyExchange() {

    clientRandom = ConnectionState::getCurrentRead()->getClientRandom();
    serverRandom = ConnectionState::getCurrentRead()->getServerRandom();
    rsaKey = ServerCertificate::getRSAPrivateKey();

}

ServerKeyExchange::~ServerKeyExchange() {
}

void ServerKeyExchange::decode(const CK::ByteArray& encoded) {

    switch (algorithm) {
        case ec_diffie_hellman:
            decodeECDH(encoded);
            break;
        default:
            throw RecordException("Invalid key exchange algorithm");
    }

}

void ServerKeyExchange::decodeECDH(const CK::ByteArray& encoded) {

    curveType = static_cast<ECCurveType>(encoded[0]);
    uint32_t index = 1;
    uint8_t length;
    uint32_t paramsLength = 1;
    switch (curveType) {
        case explicit_prime:
            {
            // Prime
            length = encoded[index++];
            paramsLength += length + 1;
            primeP.decode(encoded.range(index, length), CK::BigInteger::BIGENDIAN);
            index += length;
            // ECCurve
            length = encoded[index++];
            paramsLength += length + 1;
            curve.a.decode(encoded.range(index, length), CK::BigInteger::BIGENDIAN);
            index += length;
            length = encoded[index++];
            paramsLength += length + 1;
            curve.b.decode(encoded.range(index, length), CK::BigInteger::BIGENDIAN);
            index += length;
            // Base
            length = encoded[index++] - 1;
            paramsLength += length + 2;
            if (encoded[index++] != 0x04) {
                throw EncodingException("Invalid base point format");
            }
            baseX.decode(encoded.range(index, length / 2), CK::BigInteger::BIGENDIAN);
            index += (length / 2);
            baseY.decode(encoded.range(index, length / 2), CK::BigInteger::BIGENDIAN);
            index += (length / 2);
            // Order
            length = encoded[index++];
            paramsLength += length + 1;
            order.decode(encoded.range(index, length), CK::BigInteger::BIGENDIAN);
            index += length;
            // Cofactor
            length = encoded[index++];
            paramsLength += length + 1;
            if (length != 4) {
                throw EncodingException("Invalid cofactor length");
            }
            CK::Unsigned32 co(encoded.range(index, 4), CK::Unsigned32::BIGENDIAN);
            cofactor = co.getUnsignedValue();
            }
            break;
        case named_curve:
            {
            length = encoded[index++];
            paramsLength += length + 1;
            if (length != 2) {
                throw EncodingException("Invalid named curve length");
            }
            CK::Unsigned16 nc(encoded.range(index, 2), CK::Unsigned16::BIGENDIAN);
            index += 2;
            named = static_cast<NamedCurve>(nc.getUnsignedValue());
            switch (named) {
                case secp256r1:
                    order = CK::ECDHKeyExchange::SECP256R1.n;
                    curve.a = CK::ECDHKeyExchange::SECP256R1.a;
                    curve.b = CK::ECDHKeyExchange::SECP256R1.b;
                    baseX = CK::ECDHKeyExchange::SECP256R1.xG;
                    baseY = CK::ECDHKeyExchange::SECP256R1.yG;
                    primeP = CK::ECDHKeyExchange::SECP256R1.p;
                    cofactor = CK::ECDHKeyExchange::SECP256R1.h;
                    break;
                case secp384r1:
                    order = CK::ECDHKeyExchange::SECP384R1.n;
                    curve.a = CK::ECDHKeyExchange::SECP384R1.a;
                    curve.b = CK::ECDHKeyExchange::SECP384R1.b;
                    baseX = CK::ECDHKeyExchange::SECP384R1.xG;
                    baseY = CK::ECDHKeyExchange::SECP384R1.yG;
                    primeP = CK::ECDHKeyExchange::SECP384R1.p;
                    cofactor = CK::ECDHKeyExchange::SECP384R1.h;
                    break;
                default:
                    throw EncodingException("Invalid named curve");
            }
            }
            break;
        default:
            throw EncodingException("Invalid curve type");
    }

    length = encoded[index++];
    ecPublicKey.clear();
    ecPublicKey.append(encoded.range(index, length));
    index += length;
    CK::ByteArray serverECDH(encoded.range(0, paramsLength));
    serverECDH.append(length);
    serverECDH.append(ecPublicKey);

    CK::ByteArray hash(clientRandom);
    hash.append(serverRandom);
    hash.append(serverECDH);

    HashAlgorithm ha = static_cast<HashAlgorithm>(encoded[index++]);
    CK::Digest *digest;
    switch (ha) {
        case sha256:
            digest = new CK::SHA256;
            break;
        case sha384:
            digest = new CK::SHA384;
            break;
        case sha512:
            digest = new CK::SHA512;
            break;
        default:
            throw EncodingException("Unsupported signature hash algorithm");
    }

    SignatureAlgorithm sa = static_cast<SignatureAlgorithm>(encoded[index++]);
    CK::Unsigned16 siglen(encoded.range(index, 2), CK::Unsigned16::BIGENDIAN);
    index += 2;
    CK::ByteArray sig(encoded.range(index, siglen.getUnsignedValue()));

    switch (sa) {
        case rsa:
            {
            CK::PKCS1rsassa sign(digest);
            CK::RSAPublicKey *pubKey = ServerCertificate::getRSAPublicKey();
            if (!sign.verify(*pubKey, hash, sig)) {
                ecPublicKey.clear();
                throw EncodingException("Key not verified");
            }
            }
            break;
        default:
            throw EncodingException("Unsupported signature algorithm");
    }

}

CK::ByteArray ServerKeyExchange::encode() const {

    CK::ByteArray encoded;

    switch (algorithm) {
        case ec_diffie_hellman:
            encoded.append(encodeECDH());
            break;
        default:
            throw RecordException("Invalid key exchange algorithm");
    }

    return encoded;

}

CK::ByteArray ServerKeyExchange::encodeECDH() const {

    CK::ByteArray encoded;

    CK::ByteArray params;   // ECParameters
    params.append(curveType);
    switch (curveType) {
        case explicit_prime:
            {
            // Prime
            CK::ByteArray p(primeP.getEncoded(CK::BigInteger::BIGENDIAN));
            params.append(p.getLength());
            params.append(p);
            // ECCurve
            CK::ByteArray a(curve.a.getEncoded(CK::BigInteger::BIGENDIAN));
            params.append(a.getLength());
            params.append(a);
            CK::ByteArray b(curve.b.getEncoded(CK::BigInteger::BIGENDIAN));
            params.append(b.getLength());
            params.append(b);
            // Base
            CK::ByteArray point(1, 0x04);
            point.append(baseX.getEncoded(CK::BigInteger::BIGENDIAN));
            point.append(baseY.getEncoded(CK::BigInteger::BIGENDIAN));
            params.append(point.getLength());
            params.append(point);
            // Order
            CK::ByteArray o(order.getEncoded(CK::BigInteger::BIGENDIAN));
            params.append(o.getLength());
            params.append(o);
            // Cofactor
            CK::Unsigned32 co(cofactor);
            params.append(4);
            params.append(co.getEncoded(CK::Unsigned32::BIGENDIAN));
            }
            break;
        case named_curve:
            {
            params.append(2);
            CK::Unsigned16 nc(named);
            params.append(nc.getEncoded(CK::Unsigned16::BIGENDIAN));
            }
            break;
        default:
            throw RecordException("Invalid curve type");
    }

    CK::ByteArray pk(ecPublicKey);
    CK::ByteArray serverECDH(params);
    serverECDH.append(pk.getLength());
    serverECDH.append(pk);
    encoded.append(serverECDH);

    CK::ByteArray hash(clientRandom);
    hash.append(serverRandom);
    hash.append(serverECDH);

    CK::PKCS1rsassa sign(new CK::SHA256);
    CK::ByteArray sig(sign.sign(*rsaKey, hash));


    CK::Unsigned16 siglen(sig.getLength());
    encoded.append(sha256);
    encoded.append(rsa);
    encoded.append(siglen.getEncoded(CK::Unsigned16::BIGENDIAN));
    encoded.append(sig);

    return encoded;

}

CK::ECDHKeyExchange::CurveParams ServerKeyExchange::getCurve() const {

    CK::ECDHKeyExchange::CurveParams params;
    params.m = 0;
    params.n = order;
    params.a = curve.a;
    params.b = curve.b;
    params.xG = baseX;
    params.yG = baseY;
    params.p - primeP;
    params.h = cofactor;

    return params;

}

const CK::ByteArray& ServerKeyExchange::getECPublicKey() const {

    return ecPublicKey;

}

void ServerKeyExchange::initState(NamedCurve curve, const CK::ByteArray& pk) {

    algorithm = ec_diffie_hellman;
    curveType = named_curve;
    named = curve;
    ecPublicKey = pk;

}

void ServerKeyExchange::initState(const CK::ECDHKeyExchange::CurveParams& params,
                                                    const CK::ByteArray& pk) {

    algorithm = ec_diffie_hellman;
    curveType = explicit_prime;

    primeP = params.p;
    curve.a = params.a;
    curve.b = params.b;
    order = params.n;
    cofactor = params.h;
    baseX = params.xG;
    baseY = params.yG;

    ecPublicKey = pk;

}

void ServerKeyExchange::setAlgorithm(KeyExchangeAlgorithm alg) {

    algorithm = alg;

}

}
