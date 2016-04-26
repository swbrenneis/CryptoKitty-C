#ifndef ARMOREDDATA_H_INCLUDED
#define ARMOREDDATA_H_INCLUDED

#include "data/ByteArray.h"
#include <cstdint>
#include <iostream>

namespace CKPGP {

/**
 * @author Steve Brenneis
 *
 * This class creates the radix-64 encoded "armored"
 * output given as buffer of binary data. Binary data
 * means any kind of literal, or literal compressed data.
 * See RFC 4880, section 6.2.
 */
class ArmoredData {

    public:
        ArmoredData();
        ArmoredData(const CK::ByteArray& data);
        ~ArmoredData();

    private:
        ArmoredData(const ArmoredData& other);
        ArmoredData& operator= (const ArmoredData& other);

    public:
        void decode(std::istream& in);
        void encode(std::ostream& out);
        CK::ByteArray getData();

    private:
        uint32_t crc();
        uint8_t getTag();

    private:
        CK::ByteArray data;

    /*
     * CRC initialization values
     */
        static const uint32_t CRC24_INIT;
        static const uint32_t CRC24_POLY;

};

}

#endif // ARMOREDDATA_H_INCLUDED
