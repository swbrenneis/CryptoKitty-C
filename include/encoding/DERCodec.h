#ifndef DERCODEC_H_INCLUDED
#define DERCODEC_H_INCLUDED

#include <coder/ByteArray.h>

namespace CK {

class RSAPublicKey;
class RSAPrivateCrtKey;

class DERCodec {

    public:
        DERCodec();
        ~DERCodec();

    private:
        DERCodec(const DERCodec& other);
        DERCodec& operator= (const DERCodec& other);

    public:
        void encodeAlgorithm(coder::ByteArray& algorithm);
        void encodeBitString(coder::ByteArray& bitString, const coder::ByteArray& data);
        void encodeInteger(coder::ByteArray& integer, const coder::ByteArray& data);
        void encodeOctetString(coder::ByteArray& octetString, const coder::ByteArray& data);
        void encodeSequence(coder::ByteArray& sequence, const coder::ByteArray& data);
        int getBitString(const coder::ByteArray& source, coder::ByteArray& bitstring);
        int getInteger(const coder::ByteArray& source, coder::ByteArray& integer);
        int getOctetString(const coder::ByteArray& source, coder::ByteArray& octetstring);
        int getSegment(const coder::ByteArray& source, coder::ByteArray& segment);
        int getSequence(const coder::ByteArray& source, coder::ByteArray& sequence);
        void parseAlgorithm(const coder::ByteArray& sequence);

    private:
        void setLength(coder::ByteArray& segment, const coder::ByteArray& data);

    private:
        coder::ByteArray rsa_oid;
        coder::ByteArray der_null;

};

}

#endif // DERCODEC_H_INCLUDED

