#ifndef TBSCERTIFICATE_H_INCLUDED
#define TBSCERTIFICATE_H_INCLUDED

#include "certificates/Encodable.h"

namespace CK {

class AlgorithmIdentifier;
class Name;
class SubjectPublicKeyInfo;
class Extension;
class Validity;

class TBSCertificate : public Encodable {

    protected:
        TBSCertificate();

    public:
        virtual ~TBSCertificate();

    private:
        TBSCertificate(const TBSCertificate& other);
        TBSCertificate& operator= (const TBSCertificate& other);

    public:
        ByteArray encode() const;

    private:
        int32_t version;
        int32_t serialNumber;
        AlgorithmIdentifier *signature;
        Name *issuer;
        Validity *validity;
        Name *subject;
        SubjectPublicKeyInfo *subjectPublicKeyInfo;
        ByteArray issuerUniqueID;
        ByteArray subjectUniqueID;
        Extension *extensions;

};

}

#endif  // TBSCERTIFICATE_H_INCLUDED
