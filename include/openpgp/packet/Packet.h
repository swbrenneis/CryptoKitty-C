#ifndef PACKET_H_INCLUDED
#define PACKET_H_INCLUDED

#include "data/ByteArray.h"
#include <cstdint>

namespace CKPGP {

class Packet {

    protected:
        Packet(uint8_t t);

    public:
        virtual ~Packet();

    protected:
        Packet(const Packet& other);
        Packet& operator= (const Packet& other);

    public:
        virtual CK::ByteArray getEncoded();
        virtual uint32_t getHeaderLength() const;
        virtual uint32_t getPacketLength() const;
        virtual uint8_t getTag() const;

        static Packet *decodePacket(const CK::ByteArray& encoded);

    protected:
        virtual void encode()=0;
        virtual CK::ByteArray encodeLength() const;
        virtual uint8_t encodeTag() const;

    public:
        static const uint8_t PKESESSIONKEY;
        static const uint8_t PUBLICKEY;
        static const uint8_t PUBLICSUBKEY;
        static const uint8_t SIGNATURE;
        static const uint8_t USERID;
        static const uint8_t USERATTRIBUTE;
        static const uint8_t SECRETKEY;
        static const uint8_t ENCRYPTED;

    protected:
        uint8_t tag;
        bool newFormat;
        uint32_t packetLength;  // Length of the packet without header
        uint32_t headerLength;
        CK::ByteArray encoded;

};

}

#endif  // PACKET_H_INCLUDED
