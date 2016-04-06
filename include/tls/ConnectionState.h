#ifndef CONNECTIONSTATE_H_INCLUDED
#define CONNECTIONSTATE_H_INCLUDED

#include "data/ByteArray.h"
#include <cstdint>

namespace CKTLS {

class ConnectionState {

    public:
        enum ConnectionEnd { server, client };
        enum PRFAlgorithm { tls_prf_sha256 };
        enum BulkCipherAlgorithm { bca_null, rc4, tdes, aes };
        enum CipherType { stream, block, aead };
        enum MACAlgorithm { ma_null, hmac_md5, hmac_sha1, hmac_sha256,
                           hmac_sha384, hmac_sha512};
        enum CompressionMethod{ cm_null=0 };

    public:
        ConnectionState(ConnectionEnd e);
        ConnectionState(const ConnectionState& other);
        ConnectionState& operator= (const ConnectionState& other);
        ~ConnectionState();

    public:
        /*ConnectionEnd getConnectionEnd() const;
        PRFAlgorithm getPRFAlgorithm() const;
        BulkCipherAlgorithm getBulkCipherAlgorithm() const;
        CipherType getCipherType() const;
        MACAlgorithm getMACAlgorithm() const;
        CompressionMethod getCompressionMethod() const;*/

        // Return the initialization state.
        bool getInitialized() const;
        // Create the master secret and generate the write keys.
        void generateKeys(const CK::ByteArray& premasterSecret);
        // Get current and pending state instances.
        static const ConnectionState& getCurrentRead();
        static const ConnectionState& getCurrentWrite();
        static const ConnectionState& getPendingRead();
        static const ConnectionState& getPendingWrite();
        // Returns the current sequence number and then increments it.
        int64_t getSequenceNumber();
        // Promotes the pending read state to current and
        // initializes a new pending state.
        void promoteRead();
        // Promotes the pending write state to current and
        // initializes a new pending state.
        void promoteWrite();
        // Indicate the the state is initialized.
        void setInitialized();

    private:
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
        bool initialized;
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
