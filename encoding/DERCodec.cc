#include "encoding/DERCodec.h"
#include "exceptions/EncodingException.h"
#include "keys/RSAPublicKey.h"
#include "keys/RSAPrivateCrtKey.h"
#include <coder/Unsigned16.h>
#include <coder/Unsigned32.h>

namespace CK {

static const uint8_t INTEGER_TAG = 0x02;
static const uint8_t NULL_TAG = 0x05;
static const uint8_t BIT_STRING_TAG = 0x03;
static const uint8_t OCTET_STRING_TAG = 0x04;
static const uint8_t OID_TAG = 0x06;
static const uint8_t SEQUENCE_TAG = 0x30;

static const uint8_t DER_NULL[] = { 0x05, 0x00 };
static const uint8_t RSA_OID[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
static const int OID_LENGTH = 11;

DERCodec::DERCodec()
: rsa_oid(RSA_OID, OID_LENGTH),
  der_null(DER_NULL, 2) {
}

DERCodec::~DERCodec() {
}

void DERCodec::encodeAlgorithm(coder::ByteArray& algorithm) {

    coder::ByteArray adata(rsa_oid);
    adata.append(der_null);
    encodeSequence(algorithm, adata);

}

void DERCodec::encodeBitString(coder::ByteArray& bitstring, const coder::ByteArray& data) {

    bitstring.append(BIT_STRING_TAG);
    coder::ByteArray bitdata;
    bitdata.append(0);          // Null to indicate bitstring element.
    bitdata.append(data);
    setLength(bitstring, bitdata);
    bitstring.append(bitdata);

}

void DERCodec::encodeInteger(coder::ByteArray& integer, const coder::ByteArray& data) {

    integer.append(INTEGER_TAG);
    setLength(integer, data);
    integer.append(data);

}

void DERCodec::encodeOctetString(coder::ByteArray& octetstring, const coder::ByteArray& data) {

    octetstring.append(OCTET_STRING_TAG);
    setLength(octetstring, data);
    octetstring.append(data);

}

void DERCodec::encodeSequence(coder::ByteArray& sequence, const coder::ByteArray& data) {

    sequence.append(SEQUENCE_TAG);
    setLength(sequence, data);
    sequence.append(data);

}

int DERCodec::getBitString(const coder::ByteArray& source, coder::ByteArray& bitstring) {

    if (source[0] != BIT_STRING_TAG) {
        throw EncodingException("Not a bit string");
    }

    return getSegment(source, bitstring);

}

int DERCodec::getInteger(const coder::ByteArray& source, coder::ByteArray& integer) {

    if (source[0] != INTEGER_TAG) {
        throw EncodingException("Not an integer");
    }

    return getSegment(source, integer);

}

int DERCodec::getOctetString(const coder::ByteArray& source, coder::ByteArray& octetstring) {

    if (source[0] != OCTET_STRING_TAG) {
        throw EncodingException("Not an octet string");
    }

    return getSegment(source, octetstring);

}

int DERCodec::getSegment(const coder::ByteArray& source, coder::ByteArray& segment) {

    // The first byte is the tag.
    // BER/DER length encoding:
    // If MSB of first byte is not set, segment length is the first byte/
    // It MSB is set, lower 7 bits contant number of bytes containing the length.
    // Length is always expressed in the minimum number of bytes.
    uint32_t length;
    uint32_t index = 2;
    if (source[1] > 0x80) {
        uint32_t lengthSize = source[1] & 0x7f;
        if (lengthSize == 2) {
            coder::Unsigned16 u16(source.range(2, 2), coder::bigendian);
            length = u16.getValue();
        }
        else if (lengthSize < 5) {
            coder::ByteArray lBytes(4, 0);
            // lengthSize will be 3 or 4.
            lBytes.copy(4 - lengthSize, source.range(1, lengthSize), 0);
            coder::Unsigned32 u32(lBytes, coder::bigendian);
            length = u32.getValue();
        }
        index += lengthSize;
    }
    else {
        length = source[1];
    }
    // No buffer overruns please.
    if (index + length > source.getLength()) {
        throw EncodingException("Invalid segment length");
    }

    segment.append(source.range(index, length));
    int segLength = index + length;
    if (segLength >= static_cast<int>(source.getLength())) {
        segLength = -1;
    }
    return segLength;

}

int DERCodec::getSequence(const coder::ByteArray& source, coder::ByteArray& sequence) {

    if (source[0] != SEQUENCE_TAG) {
        throw EncodingException("Not a sequence");
    }

    return getSegment(source, sequence);

}

void DERCodec::parseAlgorithm(const coder::ByteArray& sequence) {

    if (sequence[0] != OID_TAG) {
        throw EncodingException("Invalid algorithm encoding");
    }

    coder::ByteArray oid;
    int nextSeg = getSegment(sequence, oid);
    if (nextSeg < 0 || sequence[nextSeg] != NULL_TAG || sequence[nextSeg+1] != 0) {
        throw EncodingException("Invalid algorithm encoding");
    }

}

void DERCodec::setLength(coder::ByteArray& segment, const coder::ByteArray& data) {

    uint32_t length = data.getLength();

    if (length <= 127) {
        segment.append(length & 0x7f);
    }
    else {      //  For now, there shouldn't be an integer length greater than 16 bits.
        segment.append(0x82);
        coder::Unsigned16 u16(length);
        segment.append(u16.getEncoded(coder::bigendian));
    }

}

}

