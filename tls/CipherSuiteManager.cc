#include "tls/CipherSuiteManager.h"
#include "data/Unsigned16.h"
#include "exceptions/OutOfRangeException.h"
#include "exceptions/tls/RecordException.h"

namespace CKTLS {

// Static initialization.
CipherSuiteList CipherSuiteManager::preferred;
const CipherSuite
CipherSuiteManager::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009f;
const CipherSuite
CipherSuiteManager::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009e;
const CipherSuite
CipherSuiteManager::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B;
const CipherSuite
CipherSuiteManager::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C;
const CipherSuite
CipherSuiteManager::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F;
const CipherSuite
CipherSuiteManager::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030;
const CipherSuite
CipherSuiteManager::TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D;
const CipherSuite
CipherSuiteManager::TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C;
const CipherSuite
CipherSuiteManager::TLS_NULL_WITH_NULL_NULL = 0;

CipherSuiteManager::CipherSuiteManager() {

    initialize();

}

CipherSuiteManager::~CipherSuiteManager() {
}

void CipherSuiteManager::initialize() {

    if (preferred.size() == 0) {
        preferred.push_back(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        preferred.push_back(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        preferred.push_back(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
        preferred.push_back(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
        preferred.push_back(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        preferred.push_back(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        preferred.push_back(TLS_RSA_WITH_AES_256_CBC_SHA256);
        preferred.push_back(TLS_RSA_WITH_AES_128_CBC_SHA256);
        preferred.push_back(TLS_NULL_WITH_NULL_NULL);
    }


}
void CipherSuiteManager::debugOut(std::ostream& out) const {

    for (CipherConstIter it = suites.begin(); it != suites.end(); ++it) {
        out << "Cipher suite: " << *it << std::endl;
    }

}

void CipherSuiteManager::decode(const CK::ByteArray& encoded) {

    unsigned index = 0;
    while (index < encoded.getLength()) {
        CK::Unsigned16 c(encoded.range(index, 2), CK::Unsigned16::BIGENDIAN);
        index += 2;
        suites.push_back(c.getUnsignedValue());
    }

}

CK::ByteArray CipherSuiteManager::encode() const {

    CK::ByteArray encoded;
    for (CipherConstIter it = suites.begin();
                                    it != suites.end(); ++it) {
        CK::Unsigned16 c(*it);
        encoded.append(c.getEncoded(CK::Unsigned16::BIGENDIAN));
    }

    return encoded;

}

CipherSuite CipherSuiteManager::getServerSuite() const {

    return suites.front();

}

bool CipherSuiteManager::isCurve(CipherSuite c) const {

    switch (c) {
        case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
         return true;
    }

    return false;
}

void CipherSuiteManager::loadPreferred() {

    suites.push_back(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    suites.push_back(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    suites.push_back(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
    suites.push_back(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
    suites.push_back(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
    suites.push_back(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    suites.push_back(TLS_RSA_WITH_AES_256_CBC_SHA256);
    suites.push_back(TLS_RSA_WITH_AES_128_CBC_SHA256);

}

CipherSuite CipherSuiteManager::matchCipherSuite() const {

    for (CipherConstIter pit = preferred.begin(); pit != preferred.end(); ++pit) {
        for (CipherConstIter sit = suites.begin(); sit != suites.end(); ++sit) {
            if ((*pit) == (*sit)) {
                return *pit;
            }
        }
    }

    throw RecordException("No matching cipher suite");

}

void CipherSuiteManager::setPreferred(CipherSuite suite) {

    suites.push_back(suite);

}

}

