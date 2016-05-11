#include "tls/ClientKeyExchange.h"
#include "data/Unsigned16.h"
#include "exceptions/tls/RecordException.h"
#include "exceptions/tls/EncodingException.h"

namespace CKTLS {

// Static initialization.
KeyExchangeAlgorithm ClientKeyExchange::algorithm;

ClientKeyExchange::ClientKeyExchange() {
}

ClientKeyExchange::~ClientKeyExchange() {
}

void ClientKeyExchange::decode() {

    switch (algorithm) {
        case dhe_rsa:
            decodeDH(encoded);
            break;
        case ec_diffie_hellman:
            decodeECDH(encoded);
            break;
        default:
            throw RecordException("Invalid key exchange algorithm");
    }

}

void ClientKeyExchange::decodeDH(const CK::ByteArray& encoded) {

        CK::Unsigned16 len(encoded.range(0, 2), CK::Unsigned16::BIGENDIAN);
        dYc.decode(encoded.range(2, len.getUnsignedValue()), CK::BigInteger::BIGENDIAN);

}

void ClientKeyExchange::decodeECDH(const CK::ByteArray& encoded) {
}

const CK::ByteArray& ClientKeyExchange::encode() {

    switch (algorithm) {
        case dhe_rsa:
            encoded.append(encodeDH());
            break;
        case ec_diffie_hellman:
            encoded.append(encodeECDH());
            break;
        default:
            throw RecordException("Invalid key exchange algorithm");
    }

    return encoded;

}

CK::ByteArray ClientKeyExchange::encodeDH() const {

    CK::ByteArray encoded;

    CK::ByteArray pk(dYc.getEncoded(CK::BigInteger::BIGENDIAN));
    CK::Unsigned16 len(pk.getLength());
    encoded.append(len.getEncoded(CK::Unsigned16::BIGENDIAN));
    encoded.append(pk);

    return encoded;

}

CK::ByteArray ClientKeyExchange::encodeECDH() const {

    CK::ByteArray encoded;

    return encoded;

}

const CK::BigInteger& ClientKeyExchange::getDHPublicKey() const {

    return dYc;

}

const CK::ByteArray& ClientKeyExchange::getECPublicKey() const {

    return ecPublicKey;

}

void ClientKeyExchange::initState(const CK::BigInteger& pk) {

    dYc = pk;

}

void ClientKeyExchange::initState(NamedCurve curve, const CK::ByteArray& pk) {

    algorithm = ec_diffie_hellman;
    curveType = named_curve;
    named = curve;
    ecPublicKey = pk;

}

void ClientKeyExchange::initState(const CK::ECDHKeyExchange::CurveParams& params,
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

void ClientKeyExchange::setAlgorithm(KeyExchangeAlgorithm alg) {

    algorithm = alg;

}

}
