#include "tls/ConnectionState.h"
#include "digest/SHA256.h"
#include "mac/HMAC.h"
#include "exceptions/tls/StateException.h"
#include "exceptions/BadParameterException.h"

namespace CKTLS {

// Static initialization.
ConnectionState *ConnectionState::currentRead = 0;
ConnectionState *ConnectionState::currentWrite = 0;
ConnectionState *ConnectionState::pendingRead = 0;
ConnectionState *ConnectionState::pendingWrite = 0;

ConnectionState::ConnectionState(ConnectionEnd e)
: entity(e),
  initialized(false),
  sequenceNumber(0) {
}

ConnectionState::~ConnectionState() {
}

/*
 * Generate the master secret and the client and server write keys.
 */
void ConnectionState::generateKeys(const CK::ByteArray& premasterSecret) {

    if (premasterSecret.getLength() < 48) {
        throw CK::BadParameterException("Invalid premaster key length");
    }

    CK::HMAC prf(new CK::SHA256);
    prf.setKey(premasterSecret);
    CK::ByteArray seed("master secret");
    seed.append(clientRandom);
    seed.append(serverRandom);
    prf.setMessage(seed);
    CK::ByteArray phash(prf.getHMAC());
    masterSecret.append(phash);
    while (masterSecret.getLength() < 48) {
        prf.setMessage(phash);
        phash = prf.getHMAC();
        masterSecret.append(phash);
    }
    masterSecret = masterSecret.range(0, 48);

    prf.setKey(masterSecret);
    unsigned keyLength = (encryptionKeyLength + fixedIVLength
                                                + macKeyLength) * 2;
    seed = "key expansion";
    seed.append(serverRandom);
    seed.append(clientRandom);
    prf.setMessage(seed);
    phash = prf.getHMAC();
    CK::ByteArray keyBytes(phash);
    while (keyBytes.getLength() < keyLength) {
        prf.setMessage(phash);
        phash = prf.getHMAC();
        keyBytes.append(phash);
    }
    clientWriteMACKey = keyBytes.range(0, macKeyLength);
    serverWriteMACKey = keyBytes.range(macKeyLength, macKeyLength);
    clientWriteKey = keyBytes.range(macKeyLength*2, encryptionKeyLength);
    serverWriteKey = keyBytes.range((macKeyLength*2)+encryptionKeyLength,
                                                encryptionKeyLength);
    serverWriteIV = keyBytes.range((macKeyLength*2)+(encryptionKeyLength*2),
                                                fixedIVLength);
    clientWriteIV = keyBytes.range((macKeyLength*2)+(encryptionKeyLength*2)
                                                +fixedIVLength,fixedIVLength);

}

/*
 * Manages the sequence number. Returns the current value
 * and then increments it.
 */
int64_t ConnectionState::getSequenceNumber() {

    return sequenceNumber++;

}

/*
 * promote the pending read state. Throws StateException if
 * the pending read state is uninitialized.
 */
void ConnectionState::promoteRead() {

    if (pendingRead == 0 || !pendingRead->initialized) {
        throw StateException("Pending read state not initialized.");
    }

    delete currentRead;
    currentRead = pendingRead;
    pendingRead = new ConnectionState(entity);

}

/*
 * promote the pending write state. Throws StateException if
 * the pending write state is uninitialized.
 */
void ConnectionState::promoteWrite() {

    if (pendingWrite == 0 || !pendingWrite->initialized) {
        throw StateException("Pending write state not initialized.");
    }

    delete currentWrite;
    currentWrite = pendingWrite;
    pendingWrite = new ConnectionState(entity);

}

}

