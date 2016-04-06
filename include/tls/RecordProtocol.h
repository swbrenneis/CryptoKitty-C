#ifndef RECORDPROTOCOL_H_INCLUDED
#define RECORDPROTOCOL_H_INCLUDED

#include "data/ByteArray.h"
#include "data/Scalar16.h"
#include <cstdint>

namespace CKTLS {

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
        static RecordProtocol *startRecord(uint8_t *rec);

        virtual CK::ByteArray encode() const;

    protected:
        ContentType content;
        CK::Scalar16 fragLength;
        CK::ByteArray fragment;

        static const uint8_t MAJOR;
        static const uint8_t MINOR;

};

}

#endif  // RECORDPROTOCOL_H_INCLUDED
