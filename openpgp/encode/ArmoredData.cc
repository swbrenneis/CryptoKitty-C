#include "openpgp/encode/ArmoredData.h"
#include "openpgp/encode/Radix64.h"
#include "exceptions/openpgp/EncodingException.h"
#include <cstring>

namespace CKPGP {

// Static initialization
const uint32_t ArmoredData::CRC24_INIT = 0xB704CEL;
const uint32_t ArmoredData::CRC24_POLY = 0x1864CFBL;

static const uint8_t ENCRYPTED = 9;
static const uint8_t LITERALDATA = 11;
static const uint8_t ONEPASSSIG = 4;
static const uint8_t PUBLICKEY = 6;
static const uint8_t SECRETKEY = 5;
static const uint8_t SIGNATURE = 2;

ArmoredData::ArmoredData() {
}

ArmoredData::ArmoredData(const CK::ByteArray& d)
: data(d) {
}

ArmoredData::~ArmoredData() {
}

uint32_t ArmoredData::crc() {

    uint32_t crcValue = CRC24_INIT;
    unsigned index = 0;
    while (index < data.getLength()) {
        crcValue ^= data[index++] << 16;
        for (int i = 0; i < 8; i++) {
            crcValue = crcValue << 1;
            if ((crcValue & 0x1000000) != 0) {
                crcValue ^= CRC24_POLY;
            }
        }
    }

    return crcValue;

}

/*
 * Decode incoming data and populate the raw data byte array.
 */
void ArmoredData::decode(std::istream& in) {

    CK::ByteArray bytesOut;

    char buffer[100]; // Lines are 76 characters.
    uint8_t *ubuf = reinterpret_cast<uint8_t*>(buffer);
    in.getline(buffer, 100);
    std::string line(buffer);
    if (line.find("-----") != 0) {
        throw EncodingException("Invalid message block start");
    }

    // TODO Decode message type and comments
    in.getline(buffer, 100);
    // First blank line delimits data block.
    while (buffer[0] != 0) {
        in.getline(buffer, 100);
    }
            
    //Load the encoded data into a byte array.
    in.getline(buffer, 100);
    CK::ByteArray bOut;
    while (buffer[0] != '=') {
        bOut.append(ubuf, strlen(buffer));
        in.getline(buffer, 100);
    }

    // Decodes the stream to the CRC delimiter.
    Radix64 decoder;
    decoder.decode(bOut, data);

    long crcValue = decoder.decodeCRC(std::string(buffer));
    if (crcValue != crc()) {
        throw EncodingException("CRC error");
    }

}

/*
 * Encode the data to the output stream.
 */
void ArmoredData::encode(std::ostream& out) {

    // TODO Figure out the real cases for different headers.
    std::string header("-----");
    std::string footer("-----");
    uint8_t tag = getTag();
    switch (tag) {
        case ENCRYPTED:
            header += "BEGIN PGP MESSAGE";
            footer += "END PGP MESSAGE";
            break;
        case PUBLICKEY:
            header += "BEGIN PGP PUBLIC KEY BLOCK";
            footer += "END PGP PUBLIC KEY BLOCK";
            break;
        case SECRETKEY:
            header += "BEGIN PGP SECRET KEY BLOCK";
            footer += "END PGP SECRET KEY BLOCK";
            break;
        /*case LITERALDATA:
            header += "BEGIN PGP MESSAGE, PART X/Y";
            footer += "END PGP MESSAGE, PART X/Y";
            break;
        case 5:
            header += "BEGIN PGP MESSAGE, PART X";
            footer += "END PGP MESSAGE, PART X";
            break;*/
        case SIGNATURE:
        case ONEPASSSIG:
            header += "BEGIN PGP SIGNATURE";
            footer += "END PGP SIGNATURE";
            break;
    }
    header += "-----";
    footer += "-----";
    out << header;
    out << std::endl;
    out << "Version: CryptoKitty PGP v0.1";
    out << std::endl;
    out << std::endl;

    Radix64 encoder;
    encoder.encode(data, out);

    // CRC
    out << encoder.encodeCRC(crc());
    out << std::endl;
    out << footer;
    out << std::endl;

}

/*
 * Return the decoded data.
 */
CK::ByteArray ArmoredData::getData() {

        return data;

}

/*
 * Get the packet tag.
 */
uint8_t ArmoredData::getTag() {

    uint8_t type = data[0] & 0x7f;
    uint8_t tag;
    if ((type & 0x40) != 0) {
        // New format tag.
        tag = type & 0x3f;
    }
    else {
        tag = (type >> 2) & 0x0f;
    }

    return tag;

}

}
