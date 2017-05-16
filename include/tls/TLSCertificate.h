#ifndef TLSCERTIFICATE_H_INCLUDED
#define TLSCERTIFICATE_H_INCLUDED

#include "../jni/JNIReference.h"

namespace CK {

class TLSCredentials;

class TLSCertificate : public JNIReference {

    public:
        TLSCertificate();
        ~TLSCertificate();

    private:
        TLSCertificate(const TLSCertificate& other);
        TLSCertificate& operator= (const TLSCertificate& other);

    public:
        TLSCredentials *allocateCredentials();

};

}

#endif // TLSCERTIFICATE_H_INCLUDED

