#include "openpgp/encode/Radix64.h"
#include "exceptions/openpgp/EncodingException.h"
#include "data/ByteArray.h"
#include "data/Unsigned32.h"
#include <iostream>
#include <algorithm>

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
void Radix64::decode(const CK::ByteArray& in, CK::ByteArray& out) const {

    unsigned index = 0;
    CK::ByteArray sextets(4);
    while (index < in.getLength()) {
        CK::ByteArray letters(in.range(index, 4));
        index += 4;
        for (unsigned i = 0; i < 4; ++i) {
            if (letters[i] == '=') {
                sextets[i] = 0xff;
            }
            else {
                sextets[i] = ALPHABET.find(letters[i]);
            }
        }
        uint32_t bits = 0;
        unsigned range = 3;
        if (sextets[3] != 0xff) {
            bits = sextets[3];
        }
        else {
            range = 2;
        }
        if (sextets[2] != 0xff) {
            bits = (bits << 6) | sextets[2];
        }
        else {
            range = 1;
        }
        bits = (bits << 6) | sextets[1];
        bits = (bits << 6) | sextets[0];

        CK::Unsigned32 word(bits);
        CK::ByteArray octets(word.getEncoded(CK::Unsigned32::LITTLEENDIAN));
        out.append(octets.range(0, range));
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

    uint32_t crcValue = 0;
    for (int i = 5; i > 0; --i) {
        crcValue = (crcValue << 6) | ALPHABET.find(encoded[i]);
    }

    return crcValue & 0xffffff;

}

/*
* Encode an incoming stream of data to an output stream. More
* plumbing code.
*/
void Radix64::encode(const CK::ByteArray& in, std::ostream& out) const {

    unsigned index = 0;
    int column = 0;
    CK::ByteArray sextets(4);
    unsigned bits24 = 3;
    while (index < in.getLength()) {
        unsigned count = std::min(bits24, in.getLength() - index);
        CK::ByteArray octets(in.range(index, count));
        while (octets.getLength() < 4) {
            octets.append(0);
        }
        index += count;
        CK::Unsigned32 word(octets, CK::Unsigned32::LITTLEENDIAN);
        uint32_t bits = word.getUnsignedValue();
        column = sendColumn(ALPHABET[bits & 0x3f], out, column);
        bits = bits >> 6;
        column = sendColumn(ALPHABET[bits & 0x3f], out, column);
        switch (count) {
            case 1:
                sendColumn('=', out, column);
                out << "=";
                break;
            case 2:
                bits = bits >> 6;
                sendColumn(ALPHABET[bits & 0x3f], out, column);
                out << "=";
                break;
            case 3:
                bits = bits >> 6;
                column = sendColumn(ALPHABET[bits & 0x3f], out, column);
                bits = bits >> 6;
                column = sendColumn(ALPHABET[bits & 0x3f], out, column);
                break;
        }
    }
    out << std::endl;

}

/*
 * Encode CRC value.
 */
std::string Radix64::encodeCRC(uint32_t crcValue) const {
        
    std::string encoded("=");
    uint32_t word = crcValue;
    for (int i = 0; i < 4; ++i) {
        encoded += ALPHABET[word & 0x3f];
        word = word >> 6;
    }

    return encoded;

}

int Radix64::sendColumn(char c, std::ostream& out, int column) const {

    out << c;
    if (column < 75) {
        return column + 1;
    }
    else {
        out << std::endl;
        return 0;
    }

}

}

