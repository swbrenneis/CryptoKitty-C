#include "encoding/PEMCodec.h"
#include "encoding/DERCodec.h"
#include "encoding/Base64.h"
#include "data/BigInteger.h"
#include "keys/RSAPublicKey.h"
#include "keys/RSAPrivateCrtKey.h"
#include "keys/RSAPrivateModKey.h"
#include "exceptions/EncodingException.h"
#include <coder/Unsigned16.h>
#include <coder/Unsigned32.h>
#include <memory>

namespace CK {

static const std::string RSA_PUBLIC_PREAMBLE("-----BEGIN RSA PUBLIC KEY-----");
static const std::string RSA_PUBLIC_EPILOGUE("-----END RSA PUBLIC KEY-----");
static const std::string PUBLIC_PREAMBLE("-----BEGIN PUBLIC KEY-----");
static const std::string PUBLIC_EPILOGUE("-----END PUBLIC KEY-----");
static const std::string RSA_PRIVATE_PREAMBLE("-----BEGIN RSA PRIVATE KEY-----");
static const std::string RSA_PRIVATE_EPILOGUE("-----END RSA PRIVATE KEY-----");
static const std::string PRIVATE_PREAMBLE("-----BEGIN PRIVATE KEY-----");
static const std::string PRIVATE_EPILOGUE("-----END PRIVATE KEY-----");

static const coder::ByteArray TWO_PRIME_VERSION(1, 0);
static const coder::ByteArray MULTIPRIME_VERSION(1, 1);

static const int BUFSIZE = 100;

PEMCodec::PEMCodec()
: x509Keys(false),
  derCodec(0) {
}

PEMCodec::PEMCodec(bool x509)
: x509Keys(x509),
  derCodec(0) {
}

PEMCodec::~PEMCodec() {

    delete derCodec;

}

RSAPrivateKey *PEMCodec::decodePrivateKey(std::istream& in) {

    std::unique_ptr<char[]> buf(new char[BUFSIZE]);

    // Get the preamble and key body.
    in.getline(buf.get(), BUFSIZE);
    std::string preamble(buf.get());
    Base64 base64;
    base64.decode(in, '-');

    setPrivateKeyType(in, preamble);
    derCodec = new DERCodec;
    coder::ByteArray sequence;
    int nextSeg = derCodec->getSequence(base64.getData(), sequence);
    // The sequence should include the whole array.
    if (nextSeg >= 0) {
        throw EncodingException("Invalid private key encoding");
    }

    if (x509Keys) {
        return parsePrivateKey(sequence);
    }
    else {
        // The RSA key is just a sequence of integers.
        return getPrivateKey(sequence);
    }

}

RSAPublicKey *PEMCodec::decodePublicKey(std::istream& in) {

    std::unique_ptr<char[]> buf(new char[BUFSIZE]);

    // Get the preamble and key body.
    in.getline(buf.get(), BUFSIZE);
    std::string preamble(buf.get());
    Base64 base64;
    base64.decode(in, '-');

    setPublicKeyType(in, preamble);
    derCodec = new DERCodec;
    coder::ByteArray sequence;
    int nextSeg = derCodec->getSequence(base64.getData(), sequence);
    // The sequence should include the whole array.
    if (nextSeg >= 0) {
        throw EncodingException("Invalid public key encoding");
    }

    if (x509Keys) {
        return parsePublicKey(sequence);
    }
    else {
        // The RSA key is just a sequence of integers.
        return getPublicKey(sequence);
    }

}

void PEMCodec::encode(std::ostream& out, const RSAPublicKey& publicKey) {

    out << PUBLIC_PREAMBLE << std::endl;

    derCodec = new DERCodec;
    coder::ByteArray n;
    derCodec->encodeInteger(n, publicKey.getModulus().getEncoded());
    coder::ByteArray e;
    derCodec->encodeInteger(e, publicKey.getPublicExponent().getEncoded());
    n.append(e);

    coder::ByteArray key;
    if (x509Keys) {
        // encode the integer sequence
        coder::ByteArray integers;
        derCodec->encodeSequence(integers, n);
        coder::ByteArray bitstring;
        derCodec->encodeBitString(bitstring, integers);

        // Encode the algorithm
        coder::ByteArray algorithm;
        derCodec->encodeAlgorithm(algorithm);

        // Append the bit string and encode the sequence
        algorithm.append(bitstring);
        derCodec->encodeSequence(key, algorithm);
    }
    else {
        // RSA key PEM is just the integer sequence.
        derCodec->encodeSequence(key, n);
    }

    Base64 base64(key);
    base64.encode(out);
    out << PUBLIC_EPILOGUE << std::endl;

}

void PEMCodec::encode(std::ostream& out, const RSAPublicKey& publicKey,
                                        const RSAPrivateCrtKey& privateKey) {

    out << PRIVATE_PREAMBLE << std::endl;

    derCodec = new DERCodec;

    // Encode primes
    coder::ByteArray primes;
    derCodec->encodeInteger(primes, MULTIPRIME_VERSION);
    encodePrimes(primes, publicKey, privateKey);

    coder::ByteArray key;
    if (x509Keys) {
        // encode the integer sequence
        coder::ByteArray integers;
        derCodec->encodeSequence(integers, primes);
        coder::ByteArray octetstring;
        derCodec->encodeOctetString(octetstring, integers);

        coder::ByteArray version;
        derCodec->encodeInteger(version, MULTIPRIME_VERSION);

        // Encode the algorithm and append to version.
        coder::ByteArray algorithm;
        derCodec->encodeAlgorithm(algorithm);
        version.append(algorithm);

        // Append the bit string and encode the sequence
        version.append(octetstring);
        derCodec->encodeSequence(key, version);
    }
    else {
        // RSA key PEM is just the integer sequence.
        derCodec->encodeSequence(key, primes);
    }

    Base64 base64(key);
    base64.encode(out);
    out << PRIVATE_EPILOGUE << std::endl;

}

void PEMCodec::encodePrimes(coder::ByteArray& primes, const RSAPublicKey& publicKey,
                                                        const RSAPrivateCrtKey& privateKey) {
    // Modulus.
    coder::ByteArray n;
    derCodec->encodeInteger(n, publicKey.getModulus().getEncoded());
    primes.append(n);

    // Public exponent.
    coder::ByteArray e;
    derCodec->encodeInteger(e, publicKey.getPublicExponent().getEncoded());
    primes.append(e);

    // Private exponent.
    coder::ByteArray d;
    derCodec->encodeInteger(d, privateKey.getPrivateExponent().getEncoded());
    primes.append(d);

    // First prime
    coder::ByteArray p;
    derCodec->encodeInteger(p, privateKey.getPrimeP().getEncoded());
    primes.append(p);

    // Second prime
    coder::ByteArray q;
    derCodec->encodeInteger(q, privateKey.getPrimeQ().getEncoded());
    primes.append(q);

    // First prime exponent
    coder::ByteArray expp;
    derCodec->encodeInteger(expp, privateKey.getPrimeExponentP().getEncoded());
    primes.append(expp);

    // Second prime exponent
    coder::ByteArray expq;
    derCodec->encodeInteger(expq, privateKey.getPrimeExponentQ().getEncoded());
    primes.append(expq);

    // Coefficient
    coder::ByteArray coeff;
    derCodec->encodeInteger(coeff, privateKey.getInverse().getEncoded());
    primes.append(coeff);

}

RSAPrivateKey *PEMCodec::getPrivateKey(const coder::ByteArray& key) {

    coder::ByteArray version;
    int nextSeg = derCodec->getInteger(key, version);
    if (nextSeg < 0) {
        throw EncodingException("Invalid private key encoding");
    }
    coder::ByteArray n;
    int segLength = derCodec->getInteger(key.range(nextSeg), n);
    if (segLength < 0) {
        throw EncodingException("Invalid private key encoding");
    }
    nextSeg += segLength;

    if (version[0] == TWO_PRIME_VERSION[0]) {
        coder::ByteArray d;
        segLength = derCodec->getInteger(key.range(nextSeg), d);
        if (segLength >= 0) {
            // Extra stuff in the sequence. Suspicious.
            throw EncodingException("Invalid private key encoding");
        }
        return new RSAPrivateModKey(BigInteger(n), BigInteger(d));
    }
    else if (version[0] == MULTIPRIME_VERSION[0]) {
        coder::ByteArray e;
        segLength = derCodec->getInteger(key.range(nextSeg), e);
        if (segLength < 0) {
            throw EncodingException("Invalid private key encoding");
        }
        nextSeg += segLength;
        coder::ByteArray d;
        segLength = derCodec->getInteger(key.range(nextSeg), d);
        if (segLength < 0) {
            throw EncodingException("Invalid private key encoding");
        }
        nextSeg += segLength;
        coder::ByteArray p;
        segLength = derCodec->getInteger(key.range(nextSeg), p);
        if (segLength < 0) {
            throw EncodingException("Invalid private key encoding");
        }
        nextSeg += segLength;
        coder::ByteArray q;
        segLength = derCodec->getInteger(key.range(nextSeg), q);
        if (segLength < 0) {
            throw EncodingException("Invalid private key encoding");
        }
        nextSeg += segLength;
        coder::ByteArray expp;
        segLength = derCodec->getInteger(key.range(nextSeg), expp);
        if (segLength < 0) {
            throw EncodingException("Invalid private key encoding");
        }
        nextSeg += segLength;
        coder::ByteArray expq;
        segLength = derCodec->getInteger(key.range(nextSeg), expq);
        if (segLength < 0) {
            throw EncodingException("Invalid private key encoding");
        }
        nextSeg += segLength;
        coder::ByteArray coeff;
        segLength = derCodec->getInteger(key.range(nextSeg), coeff);
        if (segLength >= 0) {
            // Extra stuff in the sequence. Suspicious.
            throw EncodingException("Invalid private key encoding");
        }
        RSAPrivateCrtKey *k = new RSAPrivateCrtKey(BigInteger(p), BigInteger(q),
                                BigInteger(expp), BigInteger(expq), BigInteger(coeff));
        k->setModulus(BigInteger(n));
        k->setPrivateExponent(BigInteger(d));
        return k;
    }
    else {
        throw EncodingException("Invalid private key encoding");
    }

}

RSAPublicKey *PEMCodec::getPublicKey(const coder::ByteArray& key) {

    coder::ByteArray n;
    int nextSeg = derCodec->getInteger(key, n);
    if (nextSeg < 0) {
        throw EncodingException("Invalid public key encoding");
    }
    coder::ByteArray e;
    nextSeg = derCodec->getInteger(key.range(nextSeg), e);
    if (nextSeg >= 0) {
        // Extra stuff in the sequence. Suspicious.
        throw EncodingException("Invalid public key encoding");
    }
    return new RSAPublicKey(BigInteger(n), BigInteger(e));

}

RSAPrivateKey *PEMCodec::parsePrivateKey(const coder::ByteArray& key) {

    coder::ByteArray version;
    int nextSeg = derCodec->getInteger(key, version);
    if (nextSeg < 0) {
        throw EncodingException("Invalid private key encoding");
    }
    coder::ByteArray algorithm;
    int segLength = derCodec->getSequence(key.range(nextSeg), algorithm);
    if (segLength < 0) {
        throw EncodingException("Invalid private key encoding");
    }
    // There is no useful data in here. We just parse it for errors.
    derCodec->parseAlgorithm(algorithm);

    nextSeg += segLength;
    // The key integers are inside of a bit string.
    coder::ByteArray octetstring;
    segLength = derCodec->getOctetString(key.range(nextSeg), octetstring);
    if (segLength >= 0) {
        // Training stuff et the end of the key. Suspicious!
        throw EncodingException("Invalid private key encoding");
    }
    coder::ByteArray sequence;
    derCodec->getSequence(octetstring, sequence);
    return getPrivateKey(sequence);

}

RSAPublicKey *PEMCodec::parsePublicKey(const coder::ByteArray& key) {

    coder::ByteArray algorithm;
    int nextSeg = derCodec->getSequence(key, algorithm);
    if (nextSeg < 0) {
        throw EncodingException("Invalid public key encoding");
    }
    // There is no useful data in here. We just parse it for errors.
    derCodec->parseAlgorithm(algorithm);

    // The key integers are inside of a bit string.
    coder::ByteArray bitstring;
    int segLength = derCodec->getBitString(key.range(nextSeg), bitstring);
    if (segLength >= 0 || bitstring[0] != 0) {
        // The leading null separates the elements of the bitstring.
        throw EncodingException("Invalid public key encoding");
    }
    coder::ByteArray sequence;
    derCodec->getSequence(bitstring.range(1), sequence);
    return getPublicKey(sequence);

}

void PEMCodec::setPrivateKeyType(std::istream& in, const std::string& preamble) {

    std::unique_ptr<char[]> buf(new char[BUFSIZE]);
    x509Keys = false;
    if (preamble == RSA_PRIVATE_PREAMBLE) {
        // Decode an RSA private key PEM stream.
        in.getline(buf.get(), BUFSIZE);
        if (std::string(buf.get()) != RSA_PRIVATE_EPILOGUE) {
            throw EncodingException("Invalid RSA epilogue");
        }
    }
    else if (preamble == PRIVATE_PREAMBLE) {
        // Decode a generic private key PEM stream.
        in.getline(buf.get(), BUFSIZE);
        if (std::string(buf.get()) != PRIVATE_EPILOGUE) {
            throw EncodingException("Invalid private key epilogue");
        }
        x509Keys = true;
    }
    else {
        // Invalid Stream
        throw EncodingException("Invalid private key preamble");
    }

}

void PEMCodec::setPublicKeyType(std::istream& in, const std::string& preamble) {

    std::unique_ptr<char[]> buf(new char[BUFSIZE]);
    x509Keys = false;
    if (preamble == RSA_PUBLIC_PREAMBLE) {
        // Decode an RSA public key PEM stream.
        in.getline(buf.get(), BUFSIZE);
        if (std::string(buf.get()) != RSA_PUBLIC_EPILOGUE) {
            throw EncodingException("Invalid RSA epilogue");
        }
    }
    else if (preamble == PUBLIC_PREAMBLE) {
        // Decode a generic public key PEM stream.
        in.getline(buf.get(), BUFSIZE);
        if (std::string(buf.get()) != PUBLIC_EPILOGUE) {
            throw EncodingException("Invalid public key epilogue");
        }
        x509Keys = true;
    }
    else {
        // Invalid Stream
        throw EncodingException("Invalid public key preamble");
    }

}

}

