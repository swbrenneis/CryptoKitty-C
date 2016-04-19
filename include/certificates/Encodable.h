#ifndef ENCODABLE_H_INCLUDED
#define ENCODABLE_H_INCLUDED

#include "data/ByteArray.h"
#include <cstdint>

namespace CK {

class Encodable {

    protected:
        Encodable();

    public:
        virtual ~Encodable();

    private:
        Encodable(const Encodable& other);
        Encodable& operator= (const Encodable& other);

    public:
        virtual ByteArray encode() const=0;

    protected:
        virtual ByteArray encodeLength(uint32_t len) const;

    protected:
        static const uint8_t UNIVERSAL;
        static const uint8_t SEQUENCE;
        static const uint8_t CONSTRUCTED;
        static const uint8_t PRIMITIVE;
        static const uint8_t BITSTRING;
        static const uint8_t OBJECTID;

};

}

#endif  // ENCODABLE_H_INCLUDED
