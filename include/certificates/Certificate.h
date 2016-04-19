#ifndef CERTIFICATE_H_INCLUDED
#define CERTIFICATE_H_INCLUDED

#include "certificates/Encodable.h"

namespace CK {

class TBSCertificate;
class AlgorithmIdentifier;

class Certificate : public Encodable {

    protected:
        Certificate();

    public:
        virtual ~Certificate();

    private:
        Certificate(const Certificate& other);
        Certificate& operator= (const Certificate& other);

    public:
        void decode(const ByteArray& encoded);
        ByteArray encode() const;
        AlgorithmIdentifier *getAlgorithm();
        TBSCertificate *getCertificate();
        ByteArray getSignature();
        void setAlgorithm(AlgorithmIdentifier *alg);
        void setCertificate(TBSCertificate *cert);
        void setSignature(const ByteArray& sig);

    private:
        TBSCertificate *tbsCertificate;
        AlgorithmIdentifier *signatureAlgorithm;
        ByteArray signatureValue;

};

}
#endif  // CERTIFICATE_H_INCLUDED
