#ifndef RECORDPROTOCOL_H_INCLUDED
#define RECORDPROTOCOL_H_INCLUDED

#include "tls/Constants.h"
#include "data/ByteArray.h"
#include <cstdint>

namespace CKTLS {

class RecordProtocol {

    protected:
        RecordProtocol(ContentType c);
        RecordProtocol(const RecordProtocol& other);

    private:
        RecordProtocol();
        RecordProtocol& operator= (const RecordProtocol& other);

    public:
        virtual ~RecordProtocol();

    public:
        virtual void decodeRecord();
        virtual ContentType decodePreamble(const CK::ByteArray& pre);
        virtual const CK::ByteArray& encodeRecord();
        const CK::ByteArray& getFragment() const;
        uint16_t getFragmentLength() const;
        uint8_t getRecordMajorVersion() const;
        uint8_t getRecordMinorVersion() const;
        ContentType getRecordType() const;
        void setFragment(const CK::ByteArray& frag);

    protected:
        virtual void decode()=0;
        virtual void encode()=0;

    protected:
        ContentType content;
        uint8_t recordMajorVersion;
        uint8_t recordMinorVersion;
        uint16_t fragLength;
        CK::ByteArray fragment;
        CK::ByteArray encoded;

        static const uint8_t MAJOR;
        static const uint8_t MINOR;

};

}

#endif  // RECORDPROTOCOL_H_INCLUDED
