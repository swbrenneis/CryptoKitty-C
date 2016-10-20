#ifndef TLSCREDENTIALS_H_INCLUDED
#define TLSCREDENTIALS_H_INCLUDED

#include "../jni/JNIReference.h"
#include <string>

namespace CK {

struct GNUTLSCredentials;

class TLSCredentials : public JNIReference {

    protected:
        TLSCredentials();

    public:
        ~TLSCredentials();

    private:
        TLSCredentials(const TLSCredentials& other);
        TLSCredentials& operator= (const TLSCredentials& other);

    public:
        enum Format { DER = 0, PEM = 1 };
        enum Security { low = 1, medium = 3, high = 4, ultra = 5 };

    public:
        static TLSCredentials *allocate();
        GNUTLSCredentials *getCredentials() { return credentials; }
        void setCRLFile(const std::string& crlpath, Format format);
        void setDiffieHellmanSecurity(Security sec);
        void setKeyFile(const std::string& certpath, const std::string& keypath,
                                                        Format format);
        void setTrustFile(const std::string& capath, Format format);

    private:
        GNUTLSCredentials *credentials;

};

}

#endif // TLSCREDENTIALS_H_INCLUDED

