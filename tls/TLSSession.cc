#include "tls/TLSSession.h"
#include "tls/TLSCredentials.h"
#include "exceptions/TLSException.h"
#include <coder/ByteArray.h>
#include <sstream>
#include <memory>
#include <gnutls/gnutls.h>

namespace CK {

struct GNUTLSSession {
    gnutls_session_t session;
    gnutls_priority_t priority;
};

struct GNUTLSCredentials {
    gnutls_certificate_credentials_t credentials;
};

TLSSession::TLSSession()
: session(new GNUTLSSession) {

    // TODO Make this configurable.
    gnutls_priority_init(&session->priority,
                        "PERFORMANCE:%SERVER_PRECEDENCE:-ARCFOUR-128", 0);

}

TLSSession::~TLSSession() {

    gnutls_deinit(session->session);
    gnutls_priority_deinit(session->priority);
    delete session;

}

bool TLSSession::doHandshake() {

    int res = gnutls_handshake(session->session);
    while (res < 0 && gnutls_error_is_fatal(res) == 0) {
        // There are a couple of non-fatal errors that can happen at the
        // transport layer. Keep trying.
        res = gnutls_handshake(session->session);
    }
    if (res < 0) {
        std::ostringstream str;
        str << "TLS handshake failed: " << gnutls_strerror(res);
        lastError = str.str();
        return false;
    }
    return true;

}

TLSSession *TLSSession::initializeClient() {

    TLSSession *sess = new TLSSession;
    gnutls_init (&sess->session->session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
    int res = gnutls_priority_set(sess->session->session, sess->session->priority);
    if (res < 0) {
        std::ostringstream str;
        str << "TLS priority initialization error: " << gnutls_strerror(res);
        throw TLSException(str.str());
    }
    gnutls_session_set_ptr(sess->session->session, sess);
    return sess;

}

TLSSession *TLSSession::initializeServer() {

    TLSSession *sess = new TLSSession;
    gnutls_init (&sess->session->session, GNUTLS_SERVER | GNUTLS_NONBLOCK);
    int res = gnutls_priority_set(sess->session->session, sess->session->priority);
    if (res < 0) {
        std::ostringstream str;
        str << "TLS priority initialization error: " << gnutls_strerror(res);
        throw TLSException(str.str());
    }
    gnutls_session_set_ptr(sess->session->session, sess);
    return sess;

}

unsigned TLSSession::receiveRecord(coder::ByteArray& record, unsigned length) {

    std::unique_ptr<uint8_t[]> buf(new uint8_t[length]);
    int res = gnutls_record_recv(session->session, static_cast<void*>(buf.get()), length);
    if (res == 0) {
        std::ostringstream str;
        str << hostname << " closed connection";
        lastError = str.str();
        return 0;
    }
    else if (res > 0) {
        record.append(buf.get(), res);
        return res;
    }
    else if (res == GNUTLS_E_REHANDSHAKE) {
        lastError = "Received a rehandshake request";
        return 0;
    }
    else {
        std::ostringstream str;
        str << "Error during record receive: " << gnutls_strerror(res);
        throw TLSException(str.str());
    }

}

void TLSSession::sendRecord(const coder::ByteArray& record) {

    std::unique_ptr<uint8_t[]> buf(record.asArray());
    int res = gnutls_record_send(session->session, static_cast<void*>(buf.get()),
                                                                    record.getLength());
    if (res < 0) {
        std::ostringstream str;
        str << "Session send error: " << gnutls_strerror(res);
        throw TLSException(str.str());
    }

}

void TLSSession::setCredentials(TLSCredentials *credentials) {

    GNUTLSCredentials *cred = credentials->getCredentials();
    int res = gnutls_credentials_set(session->session, GNUTLS_CRD_CERTIFICATE, cred->credentials);
    if (res < 0) {
        std::ostringstream str;
        str << "TLS credentials initialization error: " << gnutls_strerror(res);
        throw TLSException(str.str());
    }

}

void TLSSession::setRequireClientAuth(bool require) {

    // TODO Generalize?
    if (require) {
        gnutls_certificate_server_set_request(session->session, GNUTLS_CERT_REQUIRE);
    }

}

bool TLSSession::startSocketTransport(int socket) {

    gnutls_transport_set_int(session->session, socket);
    return true;

}

void TLSSession::tlsBye() {

    gnutls_bye(session->session, GNUTLS_SHUT_WR);

}

}

