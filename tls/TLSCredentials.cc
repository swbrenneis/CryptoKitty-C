#include "tls/TLSCredentials.h"
#include "tls/TLSSession.h"
#include "exceptions/TLSException.h"
#include <sstream>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

namespace CK {

struct GNUTLSCredentials {
    gnutls_certificate_credentials_t credentials;
};

static int verifyCertificate(gnutls_session_t session) {

    void *ptr = gnutls_session_get_ptr(session);
    TLSSession *tlsSession = reinterpret_cast<TLSSession*>(ptr);

    if (gnutls_certificate_type_get(session) == GNUTLS_CRT_X509) {
        // Verify certificate
        unsigned status;
        int res = gnutls_certificate_verify_peers2(session, &status);
        if (res < 0) {
            std::ostringstream str;
            str << "Certificate peeer verification error: " << gnutls_strerror(res);
            tlsSession->setCertError(str.str());
            return GNUTLS_E_CERTIFICATE_ERROR;
        }
        if ((status & GNUTLS_CERT_INVALID) != 0) {
            tlsSession->setCertError("Invalid certificate");
            return GNUTLS_E_CERTIFICATE_ERROR;
        }
        // Verify hostname
        //std::string hostname(reinterpret_cast<const char*>(hname));
        gnutls_x509_crt_t cert;
        gnutls_x509_crt_init(&cert);
        unsigned certListSize;
        const gnutls_datum_t *certList = gnutls_certificate_get_peers(session, &certListSize);
        if (certList == 0) {
            tlsSession->setCertError("No certificate found");
            return GNUTLS_E_CERTIFICATE_ERROR;
        }
        res = gnutls_x509_crt_import(cert, &certList[0], GNUTLS_X509_FMT_DER);
        if (res < 0) {
            std::ostringstream str;
            str << "Certificate parsing error: " << gnutls_strerror(res);
            tlsSession->setCertError(str.str());
            return GNUTLS_E_CERTIFICATE_ERROR;
        }
        if (gnutls_x509_crt_check_hostname(cert, tlsSession->getHostname().c_str())) {
            return GNUTLS_E_SUCCESS;
        }
        else {
            tlsSession->setCertError("Certificate host name mismatch");
        }
    }
    else {
        tlsSession->setCertError("Invalid certificate type");
    }

    return GNUTLS_E_CERTIFICATE_ERROR;

}

TLSCredentials::TLSCredentials()
: credentials(0) {
}

TLSCredentials::~TLSCredentials() {

    gnutls_certificate_free_credentials(credentials->credentials);
    delete credentials;

}

TLSCredentials * TLSCredentials::allocate() {

    TLSCredentials *cred = new TLSCredentials;
    GNUTLSCredentials *credentials = new GNUTLSCredentials;
    gnutls_certificate_allocate_credentials(&credentials->credentials);
    gnutls_certificate_set_verify_function(credentials->credentials, verifyCertificate);
    cred->credentials = credentials;
    return cred;

}

void TLSCredentials::setCRLFile(const std::string& crlpath, Format format) {

    if (format != DER && format != PEM) {
        throw TLSException("Illegal file format");
    }

    int res = gnutls_certificate_set_x509_crl_file(credentials->credentials, crlpath.c_str(),
                                                static_cast<gnutls_x509_crt_fmt_t>(format));
    if (res < 0) {
        std::ostringstream str;
        str << "Revocation file error: " << gnutls_strerror(res);
        throw TLSException(str.str());
    }

}

void TLSCredentials::setDiffieHellmanSecurity(Security sec) {

    switch (sec) {
        case low:
        case medium:
        case high:
        case ultra:
            break;
        default:
            throw TLSException("Illegal security value");
    }

    int bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, static_cast<gnutls_sec_param_t>(sec));
    gnutls_dh_params_t dh_params;
    gnutls_dh_params_init(&dh_params);
    gnutls_dh_params_generate2(dh_params, bits);
    gnutls_certificate_set_dh_params (credentials->credentials, dh_params);

}

void TLSCredentials::setKeyFile(const std::string& certpath, const std::string& keypath,
                                                                                Format format) {

    if (format != DER && format != PEM) {
        throw TLSException("Illegal file format");
    }

    int res = gnutls_certificate_set_x509_key_file(credentials->credentials, certpath.c_str(),
                                    keypath.c_str(), static_cast<gnutls_x509_crt_fmt_t>(format));
    if (res < 0) {
        std::ostringstream str;
        str << "Certificate file error: " << gnutls_strerror(res);
        throw TLSException(str.str());
    }

}

void TLSCredentials::setTrustFile(const std::string& capath, Format format) {

    if (format != DER && format != PEM) {
        throw TLSException("Illegal file format");
    }

    int res = gnutls_certificate_set_x509_trust_file(credentials->credentials, capath.c_str(),
                                                static_cast<gnutls_x509_crt_fmt_t>(format));
    if (res < 0) {
        std::ostringstream str;
        str << "Trust file error: " << gnutls_strerror(res);
        throw TLSException(str.str());
    }

}

}

