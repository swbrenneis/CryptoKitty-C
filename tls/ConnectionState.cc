#include "tls/ConnectionState.h"
#include "digest/SHA256.h"
#include "mac/HMAC.h"
#include "exceptions/tls/StateException.h"
#include "exceptions/BadParameterException.h"
#include <iostream>

namespace CKTLS {

// Static initialization.
ConnectionState *ConnectionState::currentRead = 0;
ConnectionState *ConnectionState::currentWrite = 0;
ConnectionState *ConnectionState::pendingRead = 0;
ConnectionState *ConnectionState::pendingWrite = 0;

ConnectionState::ConnectionState()
: initialized(false),
  prf(tls_prf_sha256),
  sequenceNumber(0) {
}

ConnectionState::~ConnectionState() {
}

ConnectionState::ConnectionState(const ConnectionState& other)
: initialized(false),
  entity(other.entity),
  prf(other.prf),
  cipher(other.cipher),
  mode(other.mode),
  mac(other.mac),
  compression(other.compression),
  encryptionKeyLength(other.encryptionKeyLength),
  blockLength(other.blockLength),
  fixedIVLength(other.fixedIVLength),
  recordIVLength(other.recordIVLength),
  macLength(other.macLength),
  macKeyLength(other.macKeyLength),
  masterSecret(other.masterSecret),
  clientRandom(other.clientRandom),
  serverRandom(other.serverRandom),
  clientWriteMACKey(other.clientWriteMACKey),
  serverWriteMACKey(other.serverWriteMACKey),
  clientWriteKey(other.clientWriteKey),
  serverWriteKey(other.serverWriteKey),
  clientWriteIV(other.clientWriteIV),
  serverWriteIV(other.serverWriteIV),
  sequenceNumber(other.sequenceNumber) {
  }

/*
 * Generate the master secret and the client and server write keys.
 */
void ConnectionState::generateKeys(const CK::ByteArray& premasterSecret) {

    masterSecret.clear();
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
    std::cout << "Master Secret = " << masterSecret << std::endl;

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

const CK::ByteArray& ConnectionState::getClientRandom() const {

    return clientRandom;

}

ConnectionState *ConnectionState::getCurrentRead() {

    if (currentRead == 0) {
        throw StateException("Current state not valid");
    }

    return currentRead;

}

ConnectionState *ConnectionState::getCurrentWrite() {

    if (currentWrite == 0) {
        throw StateException("Current state not valid");
    }

    return currentWrite;

}

/*
 * Return the connection entity.
 */
ConnectionEnd ConnectionState::getEntity() const {

    return entity;

}


ConnectionState *ConnectionState::getPendingRead() {

    if (pendingRead == 0) {
        pendingRead = new ConnectionState;
    }

    return pendingRead;

}

ConnectionState *ConnectionState::getPendingWrite() {

    if (pendingWrite == 0) {
        pendingWrite = new ConnectionState;
    }

    return pendingWrite;

}

/*
 * Manages the sequence number. Returns the current value
 * and then increments it.
 */
int64_t ConnectionState::getSequenceNumber() {

    return sequenceNumber++;

}

const CK::ByteArray& ConnectionState::getServerRandom() const {

    return serverRandom;

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
    currentRead = new ConnectionState(*pendingRead);

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
    currentWrite = new ConnectionState(*pendingWrite);

}

void ConnectionState::setClientRandom(const CK::ByteArray& rnd) {

    clientRandom = rnd;

}

void ConnectionState::setEntity(ConnectionEnd end) {

    entity = end;

}

void ConnectionState::setServerRandom(const CK::ByteArray& rnd) {

    serverRandom = rnd;

}

}

