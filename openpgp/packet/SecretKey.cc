#include "openpgp/packet/SecretKey.h"
#include "exceptions/openpgp/BadParameterException.h"
#include "exceptions/openpgp/EncodingException.h"
#include "keys/RSAPrivateCrtKey.h"
#include "coder/Unsigned16.h"
#include <cmath>
#include <time.h>

namespace CKPGP {

SecretKey::SecretKey(const PublicKey& pk)
: Packet(SECRETKEY),
  s2kUsage(0) {

      publicKey = new PublicKey(pk);

}

SecretKey::SecretKey(uint8_t tag, const PublicKey& pk)
: Packet(tag) {

      publicKey = new PublicKey(pk);

}

SecretKey::SecretKey(const CK::BigInteger& d, const CK::BigInteger& p,
                        const CK::BigInteger& q, const CK::BigInteger& inv,
                        const PublicKey& pk)
: Packet(SECRETKEY),
  s2kUsage(0),
  rsaExponent(d),
  rsap(p),
  rsaq(q),
  rsaqInv(inv) {

      publicKey = new PublicKey(pk);

}

SecretKey::SecretKey(const CK::BigInteger& x, const PublicKey& pk)
: Packet(SECRETKEY),
  s2kUsage(0) {

      if (pk.getAlgorithm() == PublicKey::DSA) {
          dsax = x;
      }
      else if (pk.getAlgorithm() == PublicKey::ELGAMAL) {
          elgamalx = x;
      }
      else {
          throw BadParameterException("Public key mismatch");
      }

      publicKey = new PublicKey(pk);

}

SecretKey::SecretKey(const coder::ByteArray& encoded)
: Packet(SECRETKEY) {

    decode(encoded);

}

SecretKey::SecretKey(const SecretKey& other)
: Packet(other),
  s2kUsage(other.s2kUsage),
  algorithm(other.algorithm),
  s2kSpecifier(other.s2kSpecifier),
  iv(other.iv),
  rsaExponent(other.rsaExponent),
  rsap(other.rsap),
  rsaq(other.rsaq),
  rsaqInv(other.rsaqInv),
  dsax(other.dsax),
  elgamalx(other.elgamalx) {

    publicKey = new PublicKey(*other.publicKey);

}

SecretKey::~SecretKey() {

    delete publicKey;

}

SecretKey& SecretKey::operator= (const SecretKey& other) {

    Packet::operator= (other);
    publicKey = new PublicKey(*other.publicKey);
    s2kUsage = other.s2kUsage;
    algorithm = other.algorithm;
    s2kSpecifier = other.s2kSpecifier;
    iv = other.iv;
    rsaExponent = other.rsaExponent;
    rsap = other.rsap;
    rsaq = other.rsaq;
    rsaqInv = other.rsaqInv;
    dsax = other.dsax;
    elgamalx = other.elgamalx;
    return *this;

}

void SecretKey::decode(const coder::ByteArray& encoded) {

    Packet *packet = decodePacket(encoded);
    if ((packet->getTag() & 0x3f) != Packet::PUBLICKEY) {
        throw BadParameterException("invalid public key");
    }
    publicKey = dynamic_cast<CKPGP::PublicKey*>(packet);

    uint32_t index = publicKey->getPacketLength();
    if (index < 192) {      // Encoded public key length
        index++;
    }
    else if (index >= 192 && index <= 8383) {
        index += 2;
    }
    else {
        index += 5;
    }
    index++;    // Encoded public key tag
    s2kUsage = encoded[index++];
    if (s2kUsage == 0xff || s2kUsage == 0xfe) {
        algorithm = encoded[index++];
        unsigned blockSize;
        switch (algorithm) {
            case 2:             // 3DES
            case 3:             // CAST5
            case 4:             // Blowfish
                blockSize = 8;
                break;
            case 7:             // AES 128
            case 8:             // AES 192
            case 9:             // AES 256
            case 10:            // Twofish
                blockSize = 16;
                break;
            default:
                throw EncodingException("Invalid block cipher algorithm");
        }

        s2kSpecifier.append(encoded[index++]);
        switch (s2kSpecifier[0]) {
            case 0:
                s2kSpecifier.append(encoded[index++]);
                break;
            case 1:
                s2kSpecifier.append(encoded.range(index, 9));
                index += 9;
                break;
            case 3:
                s2kSpecifier.append(encoded.range(index, 10));
                index += 10;
                break;
            default:
                throw EncodingException("Invalid S2K specifier");
        }

        iv = encoded.range(index, blockSize);
        index += blockSize;
    }
    // TODO: Encrypt key material
    coder::ByteArray keyMaterial(encoded.range(index, encoded.getLength() - index));
    if (s2kUsage == 0 || s2kUsage == 0xff) {
        uint16_t cksum = 0;
        for (unsigned i = 0; i < keyMaterial.getLength() - 2; ++i) {
            cksum += keyMaterial[i];
        }
        coder::Unsigned16 check(keyMaterial.range(keyMaterial.getLength() - 2, 2),
                                                            coder::bigendian);
        if (check.getValue() != cksum) {
            throw EncodingException("Key material checksum error");
        }
    }
    else {
        // TODO: s2kUsage == 0xfe
    }
 
    switch (publicKey->getAlgorithm()) {
        case 1:     // PublicKey::RSAANY
        case 2:     // PublicKey::RSAENCRYPT
        case 3:     //PublicKey::RSASIGN
            decodeRSAIntegers(keyMaterial);
            break;
        case 16:    // PublicKey::ELGAMAL
            {
            coder::Unsigned16 len(keyMaterial.range(0, 2));
            elgamalx.decode(keyMaterial.range(2, keyMaterial.getLength() - 2),
                                                                CK::BigInteger::BIGENDIAN);
            }
            break;
        case 17:    // PublicKey::DSA
            {
            coder::Unsigned16 len(keyMaterial.range(0, 2));
            dsax.decode(keyMaterial.range(2, keyMaterial.getLength() - 2),
                                                                CK::BigInteger::BIGENDIAN);
            }
            break;
    }

}

void SecretKey::decodeRSAIntegers(const coder::ByteArray& encoded) {

    coder::Unsigned16 len(encoded.range(0, 2), coder::bigendian);
    uint32_t index = 2;
    double dlen = len.getValue();
    rsaExponent.decode(encoded.range(index, ceil(dlen / 8)),
                                                    CK::BigInteger::BIGENDIAN);
    index += ceil(dlen / 8);
    len.decode(encoded.range(index, 2), coder::bigendian);
    index += 2;
    dlen = len.getValue();
    rsap.decode(encoded.range(index, ceil(dlen / 8)),
                                                    CK::BigInteger::BIGENDIAN);
    index += ceil(dlen / 8);
    len.decode(encoded.range(index, 2), coder::bigendian);
    index += 2;
    dlen = len.getValue();
    rsaq.decode(encoded.range(index, ceil(dlen / 8)),
                                                    CK::BigInteger::BIGENDIAN);
    index += ceil(dlen / 8);
    len.decode(encoded.range(index, 2), coder::bigendian);
    index += 2;
    dlen = len.getValue();
    rsaqInv.decode(encoded.range(index, ceil(dlen / 8)),
                                                    CK::BigInteger::BIGENDIAN);

}

void SecretKey::encode() {

    encoded.append(encodeTag());
    coder::ByteArray sk;

    sk.append(publicKey->getEncoded());
    sk.append(s2kUsage);
    if (s2kUsage == 0xff || s2kUsage == 0xfe) {
        sk.append(algorithm);
        sk.append(s2kSpecifier);
        sk.append(iv);
    }

    coder::ByteArray keyMaterial;
    switch (publicKey->getAlgorithm()) {
        case 1:     // PublicKey::RSAANY
        case 2:     // PublicKey::RSAENCRYPT
        case 3:     //PublicKey::RSASIGN
            keyMaterial.append(encodeRSAIntegers());
            break;
        case 16:    // PublicKey::ELGAMAL
            {
            double bits = elgamalx.bitLength();
            coder::Unsigned16 len(ceil(bits / 8));
            keyMaterial.append(len.getEncoded(coder::bigendian));
            keyMaterial.append(elgamalx.getEncoded(CK::BigInteger::BIGENDIAN));
            }
            break;
        case 17:    // PublicKey::DSA
            {
            double bits = elgamalx.bitLength();
            coder::Unsigned16 len(ceil(bits / 8));
            keyMaterial.append(len.getEncoded(coder::bigendian));
            keyMaterial.append(dsax.getEncoded(CK::BigInteger::BIGENDIAN));
            }
            break;
    }

    // TODO: Encrypt key material
    uint16_t cksum = 0;
    for (unsigned i = 0; i < keyMaterial.getLength(); ++i) {
        cksum += keyMaterial[i];
    }
    coder::Unsigned16 checksum(cksum);
    keyMaterial.append(checksum.getEncoded(coder::bigendian));

    sk.append(keyMaterial);

    packetLength = sk.getLength();
    encoded.append(encodeLength());
    encoded.append(sk);
}

coder::ByteArray  SecretKey::encodeRSAIntegers() {

    coder::ByteArray keyMaterial;

    coder::Unsigned16 len;
    len.setValue(rsaExponent.bitLength());
    keyMaterial.append(len.getEncoded(coder::bigendian));
    double bits = rsaExponent.bitLength();
    coder::ByteArray rsae(rsaExponent.getEncoded(CK::BigInteger::BIGENDIAN));
    coder::ByteArray pad1(ceil(bits / 8) - rsae.getLength());
    keyMaterial.append(pad1);
    keyMaterial.append(rsae);

    len.setValue(rsap.bitLength());
    keyMaterial.append(len.getEncoded(coder::bigendian));
    bits = rsap.bitLength();
    coder::ByteArray rsapp(rsap.getEncoded(CK::BigInteger::BIGENDIAN));
    coder::ByteArray pad2(ceil(bits / 8) - rsapp.getLength());
    keyMaterial.append(pad2);
    keyMaterial.append(rsapp);

    len.setValue(rsaq.bitLength());
    keyMaterial.append(len.getEncoded(coder::bigendian));
    bits = rsaq.bitLength();
    coder::ByteArray rsaqq(rsaq.getEncoded(CK::BigInteger::BIGENDIAN));
    coder::ByteArray pad3(ceil(bits / 8) - rsaqq.getLength());
    keyMaterial.append(pad3);
    keyMaterial.append(rsaqq);

    len.setValue(rsaqInv.bitLength());
    keyMaterial.append(len.getEncoded(coder::bigendian));
    bits = rsaqInv.bitLength();
    coder::ByteArray rsaqi(rsaqInv.getEncoded(CK::BigInteger::BIGENDIAN));
    coder::ByteArray pad4(ceil(bits / 8) - rsaqi.getLength());
    keyMaterial.append(pad4);
    keyMaterial.append(rsaqi);

    return keyMaterial;

}

CK::RSAPrivateKey *SecretKey::getRSAPrivateKey() const {

    return new CK::RSAPrivateCrtKey(rsap, rsaq, rsaExponent,
                                                publicKey->getRSAExponent());

}

void SecretKey::setPrivateKey(CK::RSAPrivateKey *pk) {

    CK::RSAPrivateCrtKey *crt = dynamic_cast<CK::RSAPrivateCrtKey*>(pk);
    rsaExponent = crt->getPrivateExponent();
    rsap = crt->getPrimeP();
    rsaq = crt->getPrimeQ();
    rsaqInv = crt->getInverse();

}

}

