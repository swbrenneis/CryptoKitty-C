#include "tls/CipherSuiteManager.h"
#include "data/Unsigned16.h"
#include "exceptions/OutOfRangeException.h"
#include "exceptions/tls/RecordException.h"

namespace CKTLS {

// Static initialization.
CipherSuiteList CipherSuiteManager::preferred;
const CipherSuite
CipherSuiteManager::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = { 0x00, 0x9f, false };
const CipherSuite
CipherSuiteManager::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = { 0x00, 0x9e, false };
const CipherSuite
CipherSuiteManager::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = { 0xC0, 0x2B, true };
const CipherSuite
CipherSuiteManager::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = { 0xC0, 0x2C, true };
const CipherSuite
CipherSuiteManager::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = { 0xC0, 0x2F, true };
const CipherSuite
CipherSuiteManager::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = { 0xC0, 0x30, true };
const CipherSuite
CipherSuiteManager::TLS_RSA_WITH_AES_256_CBC_SHA256 = { 0x00, 0x3D, false };
const CipherSuite
CipherSuiteManager::TLS_RSA_WITH_AES_128_CBC_SHA256 = { 0x00, 0x3C, false };
const CipherSuite
CipherSuiteManager::TLS_NULL_WITH_NULL_NULL = { 0, 0, false };

CipherSuiteManager::CipherSuiteManager() {

    initialize();

}

CipherSuiteManager::~CipherSuiteManager() {
}

void CipherSuiteManager::initialize() {

    if (preferred.size() == 0) {
        preferred.push_back(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
        preferred.push_back(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
        preferred.push_back(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        preferred.push_back(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        preferred.push_back(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        preferred.push_back(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        preferred.push_back(TLS_RSA_WITH_AES_256_CBC_SHA256);
        preferred.push_back(TLS_RSA_WITH_AES_128_CBC_SHA256);
        preferred.push_back(TLS_NULL_WITH_NULL_NULL);
    }


}
void CipherSuiteManager::debugOut(std::ostream& out) const {

    for (CipherConstIter it = suites.begin(); it != suites.end(); ++it) {
        CK::ByteArray s(2);
        s[0] = (*it).sel[0];
        s[1] = (*it).sel[1];
        out << "Cipher suite: " << s.toString() << std::endl;
    }

}

void CipherSuiteManager::decode(const CK::ByteArray& encoded) {

    unsigned index = 0;
    while (index < encoded.getLength()) {
        CipherSuite c;
        c.sel[0] = encoded[index++];
        if (index < encoded.getLength()) { // No overruns or underruns. Thanks anyway.
            c.sel[1] = encoded[index++];
        }
        else {
            throw RecordException("Cipher suite length invalid");
        }
        suites.push_back(c);
    }

}

CK::ByteArray CipherSuiteManager::encode() const {

    CK::ByteArray encoded;
    CK::Unsigned16 csize(suites.size() * 2);
    encoded.append(csize.getEncoded(CK::Unsigned16::BIGENDIAN));
    for (CipherConstIter it = suites.begin();
                                    it != suites.end(); ++it) {
        encoded.append(it->sel[0]);
        encoded.append(it->sel[1]);
    }

    return encoded;

}

const CipherSuite& CipherSuiteManager::matchCipherSuite() const {

    for (CipherConstIter pit = preferred.begin(); pit != preferred.end(); ++pit) {
        for (CipherConstIter sit = suites.begin(); sit != suites.end(); ++sit) {
            if ((*pit) == (*sit)) {
                return *pit;
            }
        }
    }

    throw RecordException("No matching cipher suite");

}

}

bool operator ==(const CKTLS::CipherSuite& lhs, const CKTLS::CipherSuite& rhs)
{ return lhs.sel[0] == rhs.sel[0] && lhs.sel[1] == rhs.sel[1]; } 
bool operator !=(const CKTLS::CipherSuite& lhs, const CKTLS::CipherSuite& rhs)
{ return lhs.sel[0] != rhs.sel[0] || lhs.sel[1] != rhs.sel[1]; } 
