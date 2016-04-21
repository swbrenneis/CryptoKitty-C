#include "encode/Radix64.h"
#include "exceptions/openpgp/EncodingException.h"
#include "data/ByteArray.h"

namespace CKPGP {

// Static initialization
const std::string Radix64::ALPHABET("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");

Radix64::Radix64() {
}

Radix64::~Radix64() {
}

/*
 * Decode an incoming armored stream to an output stream. Looks
 * for the CRC delimiter. Really ugly plumbing code, but it can't
 * be helped.
 */
void Radix64::decode(const CK::ByteArray& in, std::ostream& out) const {

    uint8_t sextets[4];
    unsigned index = 0;
    bool end = false;
    while (!end && index < in.getLength()) {
        CK::ByteArray letters(in.range(index, 4));
        for (int i = 0; i < 4; ++i) {
            sextets[i] = findIndex(letters[i]);
        }
        uint8_t octet = sextets[0] << 2 | ((sextets[1] >> 4) & 0x03);
        out << octet;
        octet = sextets[1] << 4;
        if (sextets[2] >= 0) {
            octet |= sextets[2] >> 2 & 0x0f;
            out << octet;
            octet = sextets[2] << 6 & 0xc0;
            if (sextets[3] >= 0) {
                octet |= sextets[3] & 0x3f;
                out << octet;
            }
            else {
                end = true;
            }
        }
        else {
            end = true;
        }
        index += 4;
    }

}

/*
* Decode a CRC encoding. String must start with '=' and must be
* 5 characters long. Throws an exception if not.
*/
uint32_t Radix64::decodeCRC(const std::string& encoded) const {

    if (encoded.length() != 5 || encoded[0] != '=') {
        throw EncodingException("Illegal CRC string");
    }

    uint8_t sextets[4];
    for (int i = 0; i < 4; ++i) {
        sextets[i] = findIndex(encoded[i+1]);
    }
    uint8_t octet = (sextets[0] << 2) | ((sextets[1] >> 4) & 0x03);
    uint32_t crcValue = (octet << 16) & 0xff0000;
    octet = (sextets[1] << 4) | ((sextets[2] >> 2) & 0x0f);
    crcValue |= (octet << 8) & 0xff00;
    octet = ((sextets[2] << 6) & 0xc0) | (sextets[3] & 0x3f);
    crcValue |= octet & 0xff;

    return crcValue;

}

/*
* Encode an incoming stream of data to an output stream. More
* plumbing code.
*/
void Radix64::encode(const CK::ByteArray& in, std::ostream& out) const {

    unsigned index = 0;
    unsigned column = 0;
    while (index < in.getLength() - 3) {
        CK::ByteArray triplet(in.range(index, 3));
        index += 3;
        // 6 MSB from first octet.
        uint8_t sextet1 = triplet[0] >> 2;
        out <<  ALPHABET[sextet1];
        column++;
        if (column == 76) {
            out << std::endl;
            column = 0;
        }
        // 2 LSB from first octet and 4 MSB from second octet.
        uint8_t sextet2 = ((triplet[0] << 4) & 0x30) | (triplet[1] >> 4);
        out << ALPHABET[sextet2];
        column++;
        if (column == 76) {
            out << std::endl;
            column = 0;
        }
        // 4 LSB from second octet and 2 MSB from third octet.
        uint8_t sextet3 = ((triplet[1] << 2) & 0x3C) | (triplet[2] >> 6);
        out << ALPHABET[sextet3];
        column++;
        if (column == 76) {
            out << std::endl;
            column = 0;
        }
        // 6 LSB from third octet.
        uint8_t sextet4 = triplet[2] & 0x3f;
        out << ALPHABET[sextet4];
        column++;
        if (column == 76) {
            out << std::endl;
            column = 0;
        }
    }

    // Do padding.
    if (in.getLength() - index == 2) {
        CK::ByteArray triplet(in.range(index, 2));
        // 6 MSB from first octet.
        uint8_t sextet1 = (triplet[0] >> 2) & 0x3f;
        out << ALPHABET[sextet1];
        column++;
        if (column == 76) {
            out << std::endl;
            column = 0;
        }
        // 2 LSB from first octet and 4 MSB from second octet.
        uint8_t sextet2 = ((triplet[0] << 4) & 0x30) | ((triplet[1] >> 4) & 0x0f);
        out << ALPHABET[sextet2];
        column++;
        if (column == 76) {
            out << std::endl;
            column = 0;
        }
        uint8_t sextet3 = (triplet[1] << 2) & 0x3C;
        out << ALPHABET[sextet3];
        column++;
        if (column == 76) {
            out << std::endl;
            column = 0;
        }
        // Pad character
        out << "=";
        column++;
        if (column == 76) {
            out << std::endl;
            column = 0;
        }
    }
    else if (in.getLength() - index == 1) {
        // 6 MSB from first octet.
        int sextet1 = (in[index] >> 2) & 0x3f;
        out << ALPHABET[sextet1];
        column++;
        if (column == 76) {
            out << std::endl;
            column = 0;
        }
        // 2 LSB from first octet and zero padding.
        int sextet2 = (in[index] << 4) & 0x30;
        out << ALPHABET[sextet2];
        column++;
        if (column == 76) {
            out << std::endl;
            column = 0;
        }
        out << "=";
        column++;
        if (column == 76) {
            out << std::endl;
            column = 0;
        }
        out << "=";
        column++;
        if (column == 76) {
            out << std::endl;
            column = 0;
        }
    }

    if (column > 0) {
        out << std::endl;
    }

}

/*
 * Encode CRC value.
 */
std::string Radix64::encodeCRC(uint32_t crcValue) const {
        
    uint8_t triplet[3];
    triplet[0] = crcValue >> 16 & 0xff;
    triplet[1] = crcValue >> 8 & 0xff;
    triplet[2] = crcValue & 0xff;

    std::string encoded("=");
    // 6 MSB from first octet.
    uint8_t sextet1 = triplet[0] >> 2;
    encoded += ALPHABET[sextet1];
    // 2 LSB from first octet and 4 MSB from second octet.
    uint8_t sextet2 = ((triplet[0] << 4) & 0x30) | ((triplet[1] >> 4) & 0x0f);
    encoded += ALPHABET[sextet2];
    // 4 LSB from second octet and 2 MSB from third octet.
    uint8_t sextet3 = ((triplet[1] << 2) & 0x3C) | ((triplet[2] >> 6) & 0x03);
    encoded += ALPHABET[sextet3];
    // 6 LSB from third octet.
    uint8_t sextet4 = triplet[2] & 0x3f;
    encoded += ALPHABET[sextet4];

    return encoded;

}

/*
 * Find the index of the radix-64 character. Returns -1 on the special
 * case of '=' (end of stream delimiter. Throws an encoding exception
 * if the index isn't found.
 */
uint8_t Radix64::findIndex(char letter) const {

    if (letter == '=') {
        return -1;
    }

    uint8_t index = 0;
    while (index < ALPHABET.length()) {
        if (ALPHABET[index] == letter) {
            return index;
        }
        index++;
    }
    throw EncodingException("Armored character out of range");

}

}

