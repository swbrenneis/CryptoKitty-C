#ifndef FINISHED_H_INCLUDED
#define FINISHED_H_INCLUDED

#include "tls/HandshakeBody.h"
#include "tls/Constants.h"

namespace CKTLS {

class Finished : public HandshakeBody {

    public:
        Finished();
        ~Finished();

    public:
        bool authenticate(const CK::ByteArray& fin) const;
        const CK::ByteArray& encode();
        void initState() {}
        void initState(const CK::ByteArray& finished);

    protected:
        void decode();

    private:
        CK::ByteArray finished;

};

}

#endif // FINISHED_H_INCLUDED
