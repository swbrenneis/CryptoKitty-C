#include "openpgp/packet/PublicKey.h"
#include "exceptions/openpgp/BadParameterException.h"
#include "exceptions/openpgp/EncodingException.h"
#include "keys/RSAPublicKey.h"
#include "coder/Unsigned32.h"
#include "coder/Unsigned16.h"
#include <cmath>
#include <time.h>

namespace CKPGP {

// Static initialization.
const uint8_t PublicKey::RSAANY = 1;
const uint8_t PublicKey::RSAENCRYPT = 2;
const uint8_t PublicKey::RSASIGN = 3;
const uint8_t PublicKey::ELGAMAL = 16;
const uint8_t PublicKey::DSA = 17;

PublicKey::PublicKey()
: Packet(PUBLICKEY),
  version(4) {
}

PublicKey::PublicKey(uint8_t tag)
: Packet(tag),
  version(4) {
}

PublicKey::PublicKey(const CK::BigInteger& m, const CK::BigInteger& e, uint8_t alg)
: Packet(PUBLICKEY),
  version(4),
  algorithm(alg),
  rsaModulus(m),
  rsaExponent(e) {

      createTime = time(0);

      switch(alg) {
          case RSASIGN:
          case RSAENCRYPT:
          case RSAANY:
              break;
          default:
              throw BadParameterException("Invalid RSA public key indicator");
      }

}

PublicKey::PublicKey(const CK::BigInteger& p, const CK::BigInteger& o,
                    const CK::BigInteger g, const CK::BigInteger& v)
: Packet(PUBLICKEY),
  version(4),
  algorithm(DSA),
  dsaPrime(p),
  dsaOrder(o),
  dsaGenerator(g),
  dsaValue(v) {

      createTime = time(0);

}

PublicKey::PublicKey(const CK::BigInteger& p, const CK::BigInteger& g,
                                            const CK::BigInteger& v)
: Packet(PUBLICKEY),
  version(4),
  algorithm(ELGAMAL),
  elgamalPrime(p),
  elgamalGenerator(g),
  elgamalValue(v) {

      createTime = time(0);

}

PublicKey::PublicKey(const coder::ByteArray& encoded)
: Packet(PUBLICKEY) {

    decode(encoded);

}

PublicKey::PublicKey(const PublicKey& other)
: Packet(other),
  version(other.version),
  createTime(other.createTime),
  algorithm(other.algorithm),
  rsaModulus(other.rsaModulus),
  rsaExponent(other.rsaExponent),
  dsaPrime(other.dsaPrime),
  dsaOrder(other.dsaOrder),
  dsaGenerator(other.dsaGenerator),
  dsaValue(other.dsaValue),
  elgamalPrime(other.elgamalPrime),
  elgamalGenerator(other.elgamalGenerator),
  elgamalValue(other.elgamalValue) {
}

PublicKey::~PublicKey() {
}

PublicKey& PublicKey::operator= (const PublicKey& other) {

    Packet::operator= (other);
    version = other.version;
    createTime = other.createTime;
    algorithm = other.algorithm;
    rsaModulus = other.rsaModulus;
    rsaExponent = other.rsaExponent;
    dsaPrime = other.dsaPrime;
    dsaOrder = other.dsaOrder;
    dsaGenerator = other.dsaGenerator;
    dsaValue = other.dsaValue;
    elgamalPrime = other.elgamalPrime;
    elgamalGenerator = other.elgamalGenerator;
    elgamalValue = other.elgamalValue;
    return *this;

}

void PublicKey::decode(const coder::ByteArray& encoded) {

    version = encoded[0];
    if (version != 4) {
        throw EncodingException("Invalid public key version");
    }

    coder::Unsigned32 created(encoded.range(1, 4), coder::bigendian);
    createTime = created.getValue();

    algorithm = encoded[5];
    switch (algorithm) {
        case RSASIGN:
        case RSAENCRYPT:
        case RSAANY:
            decodeRSAIntegers(encoded.range(6, encoded.getLength() - 6));
            break;
        case DSA:
            decodeDSAIntegers(encoded.range(6, encoded.getLength() - 6));
            break;
        case ELGAMAL:
            decodeElgamalIntegers(encoded.range(6, encoded.getLength() - 6));
            break;
        default:
            throw EncodingException("Invalid public key algorithm");
    }

}

void PublicKey::decodeDSAIntegers(const coder::ByteArray& encoded) {

    coder::Unsigned16 len(encoded.range(0, 2), coder::bigendian);
    uint32_t index = 2;
    dsaPrime.decode(encoded.range(index, len.getValue()/8),
                                                    CK::BigInteger::BIGENDIAN);
    index += len.getValue() / 8;
    len.decode(encoded.range(index, 2), coder::bigendian);
    index += 2;
    dsaOrder.decode(encoded.range(index, len.getValue()/8),
                                                    CK::BigInteger::BIGENDIAN);
    index += len.getValue() / 8;
    len.decode(encoded.range(0, 2), coder::bigendian);
    index += 2;
    dsaGenerator.decode(encoded.range(index, len.getValue()/8),
                                                    CK::BigInteger::BIGENDIAN);
    index += len.getValue() / 8;
    len.decode(encoded.range(index, 2), coder::bigendian);
    index += 2;
    dsaValue.decode(encoded.range(index, len.getValue()/8),
                                                    CK::BigInteger::BIGENDIAN);

}

void PublicKey::decodeElgamalIntegers(const coder::ByteArray& encoded) {

    coder::Unsigned16 len(encoded.range(0, 2), coder::bigendian);
    uint32_t index = 2;
    elgamalPrime.decode(encoded.range(index, len.getValue()/8),
                                                    CK::BigInteger::BIGENDIAN);
    index += len.getValue() / 8;
    len.decode(encoded.range(index, 2), coder::bigendian);
    index += 2;
    elgamalGenerator.decode(encoded.range(index, len.getValue()/8),
                                                    CK::BigInteger::BIGENDIAN);
    index += len.getValue() / 8;
    len.decode(encoded.range(index, 2), coder::bigendian);
    index += 2;
    elgamalValue.decode(encoded.range(index, len.getValue()/8),
                                                    CK::BigInteger::BIGENDIAN);

}

void PublicKey::decodeRSAIntegers(const coder::ByteArray& encoded) {

    coder::Unsigned16 len(encoded.range(0, 2), coder::bigendian);
    uint32_t index = 2;
    rsaModulus.decode(encoded.range(index, len.getValue()/8),
                                                    CK::BigInteger::BIGENDIAN);
    index += len.getValue() / 8;
    len.decode(encoded.range(index, 2), coder::bigendian);
    index += 2;
    rsaExponent.decode(encoded.range(index, len.getValue()/8),
                                                    CK::BigInteger::BIGENDIAN);

}

void PublicKey::encode() {

    encoded.append(encodeTag());
    coder::ByteArray pk;

    pk.append(version);
    coder::Unsigned32 created(createTime);
    pk.append(created.getEncoded(coder::bigendian));
    pk.append(algorithm);

    coder::Unsigned16 length;
    switch (algorithm) {
        case RSASIGN:
        case RSAENCRYPT:
        case RSAANY:
            pk.append(encodeRSAIntegers());
            break;
        case DSA:
            pk.append(encodeDSAIntegers());
            break;
        case ELGAMAL:
            pk.append(encodeElgamalIntegers());
            break;
    }

    packetLength = pk.getLength();
    encoded.append(encodeLength());
    encoded.append(pk);

}

coder::ByteArray PublicKey::encodeDSAIntegers() const {

    coder::ByteArray dsa;
    coder::Unsigned16 length;

    length.setValue(dsaPrime.bitLength());
    double len = dsaPrime.bitLength();
    dsa.append(length.getEncoded(coder::bigendian));
    coder::ByteArray dsap(dsaPrime.getEncoded(CK::BigInteger::BIGENDIAN));
    coder::ByteArray pad1(ceil(len / 8) - dsap.getLength(), 0);
    dsa.append(pad1);
    dsa.append(dsap);

    length.setValue(dsaOrder.bitLength());
    len = dsaOrder.bitLength();
    dsa.append(length.getEncoded(coder::bigendian));
    coder::ByteArray dsao(dsaOrder.getEncoded(CK::BigInteger::BIGENDIAN));
    coder::ByteArray pad2(ceil(len / 8) - dsao.getLength(), 0);
    dsa.append(pad2);
    dsa.append(dsao);

    length.setValue(dsaGenerator.bitLength());
    len = dsaGenerator.bitLength();
    dsa.append(length.getEncoded(coder::bigendian));
    coder::ByteArray dsag(dsaGenerator.getEncoded(CK::BigInteger::BIGENDIAN));
    coder::ByteArray pad3(ceil(len / 8) - dsag.getLength(), 0);
    dsa.append(pad3);
    dsa.append(dsag);

    length.setValue(dsaValue.bitLength());
    len = dsaValue.bitLength();
    dsa.append(length.getEncoded(coder::bigendian));
    coder::ByteArray dsav(dsaValue.getEncoded(CK::BigInteger::BIGENDIAN));
    coder::ByteArray pad4(ceil(len / 8) - dsav.getLength(), 0);
    dsa.append(pad4);
    dsa.append(dsav);

    return dsa;

}

coder::ByteArray PublicKey::encodeElgamalIntegers() const {

    coder::ByteArray elgamal;
    coder::Unsigned16 length;

    length.setValue(elgamalPrime.bitLength());
    double len = elgamalPrime.bitLength();
    elgamal.append(length.getEncoded(coder::bigendian));
    coder::ByteArray elgamalp(elgamalPrime.getEncoded(CK::BigInteger::BIGENDIAN));
    coder::ByteArray pad1(ceil(len / 8) - elgamalp.getLength(), 0);
    elgamal.append(pad1);
    elgamal.append(elgamalp);

    length.setValue(elgamalGenerator.bitLength());
    len = elgamalGenerator.bitLength();
    elgamal.append(length.getEncoded(coder::bigendian));
    coder::ByteArray elgamalg(elgamalGenerator.getEncoded(CK::BigInteger::BIGENDIAN));
    coder::ByteArray pad3(ceil(len / 8) - elgamalg.getLength(), 0);
    elgamal.append(pad3);
    elgamal.append(elgamalg);

    length.setValue(elgamalValue.bitLength());
    len = elgamalValue.bitLength();
    elgamal.append(length.getEncoded(coder::bigendian));
    coder::ByteArray elgamalv(elgamalValue.getEncoded(CK::BigInteger::BIGENDIAN));
    coder::ByteArray pad4(ceil(len / 8) - elgamalv.getLength(), 0);
    elgamal.append(pad4);
    elgamal.append(elgamalv);

    return elgamal;

}

coder::ByteArray PublicKey::encodeRSAIntegers() const {

    coder::ByteArray rsa;
    coder::Unsigned16 length;

    length.setValue(rsaModulus.bitLength());
    double len = rsaModulus.bitLength();
    rsa.append(length.getEncoded(coder::bigendian));
    coder::ByteArray rsam(rsaModulus.getEncoded(CK::BigInteger::BIGENDIAN));
    coder::ByteArray pad1(ceil(len / 8) - rsam.getLength(), 0);
    rsa.append(pad1);
    rsa.append(rsam);

    length.setValue(rsaExponent.bitLength());
    len = rsaExponent.bitLength();
    rsa.append(length.getEncoded(coder::bigendian));
    coder::ByteArray rsae(rsaExponent.getEncoded(CK::BigInteger::BIGENDIAN));
    coder::ByteArray pad2(ceil(len / 8) - rsae.getLength(), 0);
    rsa.append(pad2);
    rsa.append(rsae);

    return rsa;

}

uint8_t PublicKey::getAlgorithm() const {

    return algorithm;

}

const CK::BigInteger& PublicKey::getRSAExponent() const {

    return rsaExponent;

}

CK::RSAPublicKey *PublicKey::getRSAPublicKey() {

    return new CK::RSAPublicKey(rsaModulus, rsaExponent);

}

void PublicKey::setPublicKey(CK::RSAPublicKey *pk, uint8_t a) {

    switch (a) {
        case RSASIGN:
        case RSAENCRYPT:
        case RSAANY:
            algorithm = a;
            break;
        default:
            throw BadParameterException("Invalid public key algorithm");
    }

    rsaModulus = pk->getModulus();
    rsaExponent = pk->getPublicExponent();

}

}

