#include "openpgp/packet/PublicKey.h"
#include "exceptions/openpgp/BadParameterException.h"
#include "exceptions/openpgp/EncodingException.h"
#include "keys/RSAPublicKey.h"
#include "data/Unsigned32.h"
#include "data/Unsigned16.h"
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

PublicKey::PublicKey(const CK::BigInteger& m, const CK::BigInteger& e, uint8_t flag)
: Packet(PUBLICKEY),
  version(4),
  algorithm(flag),
  rsaModulus(m),
  rsaExponent(e) {

      createTime = time(0);

      switch(flag) {
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
  DSAPrime(p),
  DSAOrder(o),
  DSAGenerator(g),
  DSAValue(v) {

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

PublicKey::PublicKey(const CK::ByteArray& encoded)
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
  DSAPrime(other.DSAPrime),
  DSAOrder(other.DSAOrder),
  DSAGenerator(other.DSAGenerator),
  DSAValue(other.DSAValue),
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
    DSAPrime = other.DSAPrime;
    DSAOrder = other.DSAOrder;
    DSAGenerator = other.DSAGenerator;
    DSAValue = other.DSAValue;
    elgamalPrime = other.elgamalPrime;
    elgamalGenerator = other.elgamalGenerator;
    elgamalValue = other.elgamalValue;
    return *this;

}

void PublicKey::decode(const CK::ByteArray& encoded) {

    version = encoded[0];
    if (version != 4) {
        throw EncodingException("Invalid public key version");
    }

    CK::Unsigned32 created(encoded.range(1, 4), CK::Unsigned32::BIGENDIAN);
    createTime = created.getUnsignedValue();

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

void PublicKey::decodeDSAIntegers(const CK::ByteArray& encoded) {

    CK::Unsigned16 len(encoded.range(0, 2), CK::Unsigned16::BIGENDIAN);
    uint32_t index = 2;
    DSAPrime = CK::BigInteger(encoded.range(index, len.getUnsignedValue()/8),
                                                    CK::BigInteger::BIGENDIAN);
    index += len.getUnsignedValue();
    len = CK::Unsigned16(encoded.range(index, 2));
    index += 2;
    DSAOrder = CK::BigInteger(encoded.range(index, len.getUnsignedValue()/8),
                                                    CK::BigInteger::BIGENDIAN);
    index += len.getUnsignedValue();
    len = CK::Unsigned16(encoded.range(0, 2), CK::Unsigned16::BIGENDIAN);
    index += 2;
    DSAGenerator = CK::BigInteger(encoded.range(index, len.getUnsignedValue()/8),
                                                    CK::BigInteger::BIGENDIAN);
    index += len.getUnsignedValue();
    len = CK::Unsigned16(encoded.range(index, 2));
    index += 2;
    DSAValue = CK::BigInteger(encoded.range(index, len.getUnsignedValue()/8),
                                                    CK::BigInteger::BIGENDIAN);

}

void PublicKey::decodeElgamalIntegers(const CK::ByteArray& encoded) {

    CK::Unsigned16 len(encoded.range(0, 2), CK::Unsigned16::BIGENDIAN);
    uint32_t index = 2;
    elgamalPrime = CK::BigInteger(encoded.range(index, len.getUnsignedValue()/8),
                                                    CK::BigInteger::BIGENDIAN);
    index += len.getUnsignedValue();
    len = CK::Unsigned16(encoded.range(index, 2));
    index += 2;
    elgamalGenerator = CK::BigInteger(encoded.range(index, len.getUnsignedValue()/8),
                                                    CK::BigInteger::BIGENDIAN);
    index += len.getUnsignedValue();
    len = CK::Unsigned16(encoded.range(index, 2));
    index += 2;
    elgamalValue = CK::BigInteger(encoded.range(index, len.getUnsignedValue()/8),
                                                    CK::BigInteger::BIGENDIAN);

}

void PublicKey::decodeRSAIntegers(const CK::ByteArray& encoded) {

    CK::Unsigned16 len(encoded.range(0, 2), CK::Unsigned16::BIGENDIAN);
    uint32_t index = 2;
    rsaModulus = CK::BigInteger(encoded.range(index, len.getUnsignedValue()/8),
                                                    CK::BigInteger::BIGENDIAN);
    index += len.getUnsignedValue();
    len = CK::Unsigned16(encoded.range(index, 2));
    index += 2;
    rsaExponent = CK::BigInteger(encoded.range(index, len.getUnsignedValue()/8),
                                                    CK::BigInteger::BIGENDIAN);

}

void PublicKey::encode() {

    encoded.append(encodeTag());
    CK::ByteArray pk;

    pk.append(version);
    CK::Unsigned32 created(createTime);
    pk.append(created.getEncoded(CK::Unsigned32::BIGENDIAN));
    pk.append(algorithm);

    CK::Unsigned16 length;
    switch (algorithm) {
        case RSASIGN:
        case RSAENCRYPT:
        case RSAANY:
            length.setValue(rsaModulus.bitLength());
            pk.append(length.getEncoded(CK::Unsigned16::BIGENDIAN));
            pk.append(rsaModulus.getEncoded(CK::BigInteger::BIGENDIAN));
            length.setValue(rsaExponent.bitLength());
            pk.append(length.getEncoded(CK::Unsigned16::BIGENDIAN));
            pk.append(rsaExponent.getEncoded(CK::BigInteger::BIGENDIAN));
            break;
        case DSA:
            length.setValue(DSAPrime.bitLength());
            pk.append(length.getEncoded(CK::Unsigned16::BIGENDIAN));
            pk.append(DSAPrime.getEncoded(CK::BigInteger::BIGENDIAN));
            length.setValue(DSAOrder.bitLength());
            pk.append(length.getEncoded(CK::Unsigned16::BIGENDIAN));
            pk.append(DSAOrder.getEncoded(CK::BigInteger::BIGENDIAN));
            length.setValue(DSAGenerator.bitLength());
            pk.append(length.getEncoded(CK::Unsigned16::BIGENDIAN));
            pk.append(DSAGenerator.getEncoded(CK::BigInteger::BIGENDIAN));
            length.setValue(DSAValue.bitLength());
            pk.append(length.getEncoded(CK::Unsigned16::BIGENDIAN));
            pk.append(DSAValue.getEncoded(CK::BigInteger::BIGENDIAN));
            break;
        case ELGAMAL:
            length.setValue(elgamalPrime.bitLength());
            pk.append(length.getEncoded(CK::Unsigned16::BIGENDIAN));
            pk.append(elgamalPrime.getEncoded(CK::BigInteger::BIGENDIAN));
            length.setValue(elgamalGenerator.bitLength());
            pk.append(length.getEncoded(CK::Unsigned16::BIGENDIAN));
            pk.append(elgamalGenerator.getEncoded(CK::BigInteger::BIGENDIAN));
            length.setValue(elgamalValue.bitLength());
            pk.append(length.getEncoded(CK::Unsigned16::BIGENDIAN));
            pk.append(elgamalValue.getEncoded(CK::BigInteger::BIGENDIAN));
            break;
    }

    packetLength = pk.getLength();
    encoded.append(encodeLength());
    encoded.append(pk);

}

uint8_t PublicKey::getAlgorithm() const {

    return algorithm;

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
    rsaExponent = pk->getExponent();

}

}

