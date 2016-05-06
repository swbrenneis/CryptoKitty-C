#ifndef CIPHERSUITEMANAGER_H_INCLUDED
#define CIPHERSUITEMANAGER_H_INCLUDED

#include "data/ByteArray.h"
#include "tls/Constants.h"
#include <cstdint>
#include <deque>
#include <iostream>

namespace CKTLS {

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

    private:
        CipherSuiteList suites;
        static CipherSuiteList preferred;

};

}

#endif  // CIPHERSUITEMANAGER_H_INCLUDED
