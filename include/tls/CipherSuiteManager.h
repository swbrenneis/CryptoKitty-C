#ifndef CIPHERSUITEMANAGER_H_INCLUDED
#define CIPHERSUITEMANAGER_H_INCLUDED

#include "data/ByteArray.h"
#include <cstdint>
#include <deque>
#include <iostream>

namespace CKTLS {

typedef uint16_t CipherSuite;
typedef std::deque<CipherSuite> CipherSuiteList;
typedef CipherSuiteList::const_iterator CipherConstIter;
typedef CipherSuiteList::iterator CipherIter;

/*
 * Singleton.
 */
class CipherSuiteManager {

    public:
        CipherSuiteManager();
        ~CipherSuiteManager();

    private:
        CipherSuiteManager(const CipherSuiteManager& other);
        CipherSuiteManager& operator= (const CipherSuiteManager& other);

    public:
        void debugOut(std::ostream& out) const;
        void decode(const CK::ByteArray& encoded);
        CK::ByteArray encode() const;
        CipherSuite getServerSuite() const;
        bool isCurve(CipherSuite c) const;
        void loadPreferred();
        CipherSuite matchCipherSuite() const;
        void setPreferred(CipherSuite c);

    private:
        void initialize();

    public:
        static const CipherSuite TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
        static const CipherSuite TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;
        static const CipherSuite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        static const CipherSuite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
        static const CipherSuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
        static const CipherSuite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
        static const CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA256;
        static const CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA256;
        static const CipherSuite TLS_NULL_WITH_NULL_NULL;

    private:
        CipherSuiteList suites;
        static CipherSuiteList preferred;

};

}

#endif  // CIPHERSUITEMANAGER_H_INCLUDED
