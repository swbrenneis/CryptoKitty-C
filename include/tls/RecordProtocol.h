#ifndef RECORDPROTOCOL_H_INCLUDED
#define RECORDPROTOCOL_H_INCLUDED

#include "data/ByteArray.h"
#include <cstdint>

namespace CKTLS {

class HandshakeBody;

class RecordProtocol {

    public:
        enum ContentType { change_cipher_spec=20, alert=21, handshake=22,
                            application_data=23 };

    protected:
        RecordProtocol(ContentType c);
        RecordProtocol(const RecordProtocol& other);

    private:
        RecordProtocol();
        RecordProtocol& operator= (const RecordProtocol& other);

    public:
        virtual ~RecordProtocol();

    public:
        virtual void decode(const CK::ByteArray& frag)=0;
        virtual CK::ByteArray encode()=0;
        uint16_t getFragmentLength() const;
        uint8_t getRecordMajorVersion() const;
        uint8_t getRecordMinorVersion() const;
        ContentType getType() const;
        void setFragmentLength(uint16_t len);
        void setRecordMajorVersion(uint8_t major);
        void setRecordMinorVersion(uint8_t minor);
        void setType(ContentType c);

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

#endif  // RECORDPROTOCOL_H_INCLUDED
