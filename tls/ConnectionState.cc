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
  compression(cm_null),
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
  sequenceNumber(0) {
  }

/*
 * Copies the pending write state to the pending read state.
 */
void ConnectionState::copyWriteToRead() {

    ConnectionEnd end = pendingRead->entity;
    delete pendingRead;
    pendingRead = new ConnectionState(*pendingWrite);
    pendingRead->entity = end;

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
    //std::cout << "Master Secret = " << masterSecret << std::endl;

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

BulkCipherAlgorithm ConnectionState::getCipherAlgorithm() const {

    return cipher;

}

CipherType ConnectionState::getCipherType() const {

    return mode;

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

const CK::ByteArray& ConnectionState::getEncryptionKey() const {

    return entity == server ? clientWriteKey : serverWriteKey;

}

uint32_t ConnectionState::getEncryptionKeyLength() const {

    return encryptionKeyLength * 8;

}

const CK::ByteArray& ConnectionState::getIV() const {

    return entity == server ? clientWriteIV : serverWriteIV;

}

const CK::ByteArray& ConnectionState::getMacKey() const {

    return entity == server ? clientWriteMACKey : serverWriteMACKey;

}

/*
 * Return the connection entity.
 */
ConnectionEnd ConnectionState::getEntity() const {

    return entity;

}

MACAlgorithm ConnectionState::getHMAC() const {

    return mac;

}

uint32_t ConnectionState::getMacKeyLength() const {

    return macKeyLength;

}

const CK::ByteArray& ConnectionState::getMasterSecret() const {

    return masterSecret;

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
 * Returns the current sequence number.
 */
int64_t ConnectionState::getSequenceNumber() const {

    return sequenceNumber;

}

const CK::ByteArray& ConnectionState::getServerRandom() const {

    return serverRandom;

}

/*
 * Increments the current sequence number.
 */
void ConnectionState::incrementSequence() {

    sequenceNumber++;

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

void ConnectionState::setCipherAlgorithm(BulkCipherAlgorithm alg) {

    cipher = alg;

    switch (cipher) {
        case rc4:
            // TODO
            break;
        case tdes:
            // TODO
            break;
        case aes:
            blockLength = 16;
            if (mode == block) {
                fixedIVLength = 16;
            }
            break;
        default:
            throw StateException("Invalid block cipher algorithm");
    }

}

void ConnectionState::setCipherType(CipherType type) {

    mode = type;

    switch (mode) {
        case stream:
            // Needs RC4 cipher.
            break;
        case block:
            // CBC mode. IV length = cipher block lenght
            break;
        case aead:
            // GCM mode. IV length = 12 for performance reasons.
            fixedIVLength = 12;
            break;
        default:
            throw StateException("Invalid HMAC algorithm");
    }

}

void ConnectionState::setClientRandom(const CK::ByteArray& rnd) {

    clientRandom = rnd;

}

void ConnectionState::setEncryptionKeyLength(uint32_t keyLength) {

    if (keyLength % 8 != 0) {
        throw CK::BadParameterException("Invalid key size");
    }

    encryptionKeyLength = keyLength / 8;

}

void ConnectionState::setEntity(ConnectionEnd end) {

    entity = end;

}

void ConnectionState::setHMAC(MACAlgorithm m) {

    mac = m;

    switch (mac) {
        case mac_null:
            macLength = 0;
            break;
        case hmac_md5:
            macLength = macKeyLength = 16;
            break;
        case hmac_sha1:
            macLength = macKeyLength = 20;
            break;
        case hmac_sha256:
            macLength = macKeyLength = 32;
            break;
        case hmac_sha384:
            macLength = macKeyLength = 48;
            break;
        case hmac_sha512:
            macLength = macKeyLength = 64;
            break;
        default:
            throw StateException("Invalid HMAC algorithm");
    }

}

void ConnectionState::setInitialized() {

    initialized = true;

}

void ConnectionState::setServerRandom(const CK::ByteArray& rnd) {

    serverRandom = rnd;

}

}

