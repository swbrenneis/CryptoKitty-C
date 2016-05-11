#ifndef CONNECTIONSTATE_H_INCLUDED
#define CONNECTIONSTATE_H_INCLUDED

#include "tls/Constants.h"
#include "data/ByteArray.h"
#include <cstdint>

namespace CKTLS {

class ConnectionState {

    public:
        ConnectionState();
        ConnectionState(const ConnectionState& other);
        ConnectionState& operator= (const ConnectionState& other);
        ~ConnectionState();

    public:
        // Convenience routine. Copies the pending write state to the pending
        // read state.
        void copyWriteToRead();
        // Generate the cyptography variables.
        void generateKeys(const CK::ByteArray& premasterSecret);
        // Get the block cipher algorithm.
        BulkCipherAlgorithm getCipherAlgorithm() const;
        // Get the block cipher mode.
        CipherType getCipherType() const;
        // Get the client random bytes for signatures.
        const CK::ByteArray& getClientRandom() const;
        // Get the key for block encryption.
        const CK::ByteArray& getEncryptionKey() const;
        // gets the length of the block encryption key.
        uint32_t getEncryptionKeyLength() const;
        // Get the key for HMAC authentication.
        const CK::ByteArray& getMacKey() const;
        // Get the IV for block encryption.
        const CK::ByteArray& getIV() const;
        // Gets the connection end entity.
        ConnectionEnd getEntity() const;
        // Returns the HMAC algorithm.
        MACAlgorithm getHMAC() const;
        // Return the initialization state.
        bool getInitialized() const;
        // Get the HMAC key length.
        uint32_t getMacKeyLength() const;
        // Get the master secret.
        const CK::ByteArray& getMasterSecret() const;
        // Returns the pseudorandom algorithm.
        PRFAlgorithm getPRF() const;
        // Returns the current sequence number and then increments it.
        int64_t getSequenceNumber() const;
        // Get the server random bytes for signatures.
        const CK::ByteArray& getServerRandom() const;
        // Create the master secret and generate the write keys.
        // Get current and pending state instances.
        static ConnectionState *getCurrentRead();
        static ConnectionState *getCurrentWrite();
        static ConnectionState *getPendingRead();
        static ConnectionState *getPendingWrite();
        // Increment the sequence number.
        void incrementSequence();
        // Promotes the pending read state to current and
        // initializes a new pending state.
        void promoteRead();
        // Promotes the pending write state to current and
        // initializes a new pending state.
        void promoteWrite();
        // Sets the block cipher algorithm.
        void setCipherAlgorithm(BulkCipherAlgorithm alg);
        // Sets the cipher mode.
        void setCipherType(CipherType type);
        // Sets the client random value for signatures.
        void setClientRandom(const CK::ByteArray& rnd);
        // Sets the encryption key length.
        void setEncryptionKeyLength(uint32_t length);
        // Sets the connection end entity.
        void setEntity(ConnectionEnd end);
        // Sets the MAC algorithm.
        void setHMAC(MACAlgorithm m);
        // Indicate the the state is initialized.
        void setInitialized();
        // Sets the server random value for signatures.
        void setServerRandom(const CK::ByteArray& rnd);

    private:
        bool initialized;
        ConnectionEnd entity;
        PRFAlgorithm prf;               // Fixed value. Cannot be set.
        BulkCipherAlgorithm cipher;
        CipherType mode;
        MACAlgorithm mac;
        CompressionMethod compression;  // Fixed value. Cannot be set.
        uint32_t encryptionKeyLength;
        uint32_t blockLength;
        uint32_t fixedIVLength;
        uint32_t recordIVLength;
        uint32_t macLength;
        uint32_t macKeyLength;
        // uint8_t master_secret[48];
        CK::ByteArray masterSecret;
        // uint8_t client_random[32];
        CK::ByteArray clientRandom;
        // uint8_t server_random[32];
        CK::ByteArray serverRandom;
        CK::ByteArray clientWriteMACKey; 
        CK::ByteArray serverWriteMACKey; 
        CK::ByteArray clientWriteKey; 
        CK::ByteArray serverWriteKey; 
        CK::ByteArray clientWriteIV; 
        CK::ByteArray serverWriteIV; 
        int64_t sequenceNumber;


        /*
         * For no apparent reason, they decided to make the
         * names of thee things really obscure. Client write is used
         * by the server to read incoming client records. Server write
         * is used by the client to read incoming record from the
         * server. Client read is used to send outgoing records to
         * the client. Server read is used to send outgoing records
         * to the server
         */
        static ConnectionState *currentRead;
        static ConnectionState *currentWrite;
        static ConnectionState *pendingRead;
        static ConnectionState *pendingWrite;

};

}

#endif  // CONNECTIONSTATE_H_INCLUDED
