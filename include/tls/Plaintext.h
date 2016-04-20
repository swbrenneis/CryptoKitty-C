#ifndef PLAINTEXT_H_INCLUDED
#define PLAINTEXT_H_INCLUDED

#include "data/ByteArray.h"
#include <cstdint>

namespace CKTLS {

class Plaintext {

    public:
        enum ContentType { change_cipher_spec=20, alert=21, handshake=22,
                            application_data=23 };

    protected:
        Plaintext(ContentType c);
        Plaintext(const Plaintext& other);

    private:
        Plaintext();
        Plaintext& operator= (const Plaintext& other);

    public:
        virtual ~Plaintext();

    public:
        ContentType decodePreamble(const CK::ByteArray& encoded);
        virtual void decode()=0;
        virtual CK::ByteArray encode()=0;
        uint16_t getFragmentLength() const;
        ContentType getContentType() const;
        void setFragment(const CK::ByteArray& frag);

    protected:
        CK::ByteArray encodePreamble() const;

    protected:
        ContentType content;
        uint8_t recordMajorVersion;
        uint8_t recordMinorVersion;
        uint16_t fragLength;
        CK::ByteArray fragment;

        static const uint8_t MAJOR;
        static const uint8_t MINOR;

};

}

#endif  // PLAINTEXT_H_INCLUDED
