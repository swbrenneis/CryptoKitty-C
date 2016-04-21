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

    private:
        Packet(const Packet& other);
        Packet& operator= (const Packet& other);

    public:
        virtual CK::ByteArray encode() const=0;
        virtual uint8_t getTag() const;

    protected:
        uint8_t encodeTag() const;

    protected:
        uint8_t tag;
        bool newFormat;

        static const uint8_t PKESESSIONKEY;
        static const uint8_t PUBLICKEY;
        static const uint8_t SIGNATURE;
        static const uint8_t USERID;
        static const uint8_t USERATTRIBUTE;

};

}

#endif  // PACKET_H_INCLUDED
