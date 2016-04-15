#include "tls/CipherSuiteManager.h"
#include "exceptions/OutOfRangeException.h"

namespace CKTLS {

// Static initialization.
const CipherSuite CipherSuiteManager::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = { 0x00, 0x9f };
const CipherSuite CipherSuiteManager::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = { 0x00, 0x9e };
const CipherSuite CipherSuiteManager::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = { 0xC0, 0x2B };
const CipherSuite CipherSuiteManager::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = { 0xC0, 0x2C };
const CipherSuite CipherSuiteManager::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = { 0xC0, 0x2F };
const CipherSuite CipherSuiteManager::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = { 0xC0, 0x30 };
const CipherSuite CipherSuiteManager::TLS_RSA_WITH_AES_256_CBC_SHA256 = { 0x00, 0x3D };
const CipherSuite CipherSuiteManager::TLS_RSA_WITH_AES_128_CBC_SHA256 = { 0x00, 0x3C };
const CipherSuite CipherSuiteManager::TLS_NULL_WITH_NULL_NULL = { 0, 0 };
static CipherSuiteManager *theManager = 0;

CipherSuiteManager::CipherSuiteManager() {
}

CipherSuiteManager::~CipherSuiteManager() {
}

CipherSuiteManager *CipherSuiteManager::getManager() {

    if (theManager == 0) {
        theManager = new CipherSuiteManager;
        theManager->initialize();
    }

    return theManager;
}

void CipherSuiteManager::initialize() {

    suites.push_back(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
    suites.push_back(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
    suites.push_back(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
    suites.push_back(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    suites.push_back(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    suites.push_back(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    suites.push_back(TLS_RSA_WITH_AES_256_CBC_SHA256);
    suites.push_back(TLS_RSA_WITH_AES_128_CBC_SHA256);
    suites.push_back(TLS_NULL_WITH_NULL_NULL);

}

const CipherSuite& CipherSuiteManager::nextCipherSuite(unsigned next) const {

    if (next >= suites.size()) {
        throw CK::OutOfRangeException("Cipher index out of bounds");
    }

    return suites[next];

}

}

bool operator ==(const CKTLS::CipherSuite& lhs, const CKTLS::CipherSuite& rhs)
{ return lhs.sel[0] == rhs.sel[0] && lhs.sel[1] == rhs.sel[1]; } 
bool operator !=(const CKTLS::CipherSuite& lhs, const CKTLS::CipherSuite& rhs)
{ return lhs.sel[0] != rhs.sel[0] || lhs.sel[1] != rhs.sel[1]; } 
