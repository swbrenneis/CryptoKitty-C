#ifndef PLAINTEXT_H_INCLUDED
#define PLAINTEXT_H_INCLUDED

#include "tls/RecordProtocol.h"

namespace CKTLS {

class Plaintext : public RecordProtocol {

    protected:
        Plaintext(ContentType c);

    public:
        virtual ~Plaintext();

    private:
        Plaintext(const Plaintext& other);
        Plaintext& operator= (const Plaintext& other);

    public:
        static Plaintext *startRecord(const CK::ByteArray& header);

    /*public:
        void decode(const CK::ByteArray& encoded);
        CK::ByteArray encode() const;*/

};

}

#endif  // PLAINTEXT_H_INCLUDED
