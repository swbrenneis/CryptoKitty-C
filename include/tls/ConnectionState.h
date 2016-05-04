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
        /*PRFAlgorithm getPRFAlgorithm() const;
        BulkCipherAlgorithm getBulkCipherAlgorithm() const;
        CipherType getCipherType() const;
        MACAlgorithm getMACAlgorithm() const;
        CompressionMethod getCompressionMethod() const;*/

        void generateKeys(const CK::ByteArray& premasterSecret);
        // Get the client random bytes for signatures.
        const CK::ByteArray& getClientRandom() const;
        // Gets the connection end entity.
        ConnectionEnd getEntity() const;
        // Return the initialization state.
        bool getInitialized() const;
        // Returns the pseudorandom algorithm.
        PRFAlgorithm getPRF() const;
        // Returns the current sequence number and then increments it.
        int64_t getSequenceNumber();
        // Get the server random bytes for signatures.
        const CK::ByteArray& getServerRandom() const;
        // Create the master secret and generate the write keys.
        // Get current and pending state instances.
        static ConnectionState *getCurrentRead();
        static ConnectionState *getCurrentWrite();
        static ConnectionState *getPendingRead();
        static ConnectionState *getPendingWrite();
        // Promotes the pending read state to current and
        // initializes a new pending state.
        void promoteRead();
        // Promotes the pending write state to current and
        // initializes a new pending state.
        void promoteWrite();
        // Sets the client random value for signatures.
        void setClientRandom(const CK::ByteArray& rnd);
        // Sets the connection end entity.
        void setEntity(ConnectionEnd end);
        // Indicate the the state is initialized.
        void setInitialized();
        // Sets the calculated master secret.
        void setMasterSecret(const CK::ByteArray& secret);
        // Sets the server random value for signatures.
        void setServerRandom(const CK::ByteArray& rnd);

    private:
        bool initialized;
        ConnectionEnd entity;
        PRFAlgorithm prf;
        BulkCipherAlgorithm cipher;
        CipherType mode;
        MACAlgorithm mac;
        CompressionMethod compression;
        uint8_t encryptionKeyLength;
        uint8_t blockLength;
        uint8_t fixedIVLength;
        uint8_t recordIVLength;
        uint8_t macLength;
        uint8_t macKeyLength;
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
