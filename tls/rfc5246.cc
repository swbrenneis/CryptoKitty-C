#include "data/ByteArray.h"
#include "mac/HMAC.h"
#include "digest/SHA256.h"
#include <cstdio>

namespace CK {

// Values not evaluated.
typedef uint8_t opaque;
// Big-endian order.
typedef uint8_t uint16[2];
typedef uint8_t uint24[3];
typedef uint8_t uint32[4];
typedef uint8_t uint64[8];

// Handled as uint8_t. Section 7.4.1.4.1
enum HashAlgorithm { none=0, md5=1, sha1=2, sha224=3, sha256=4,
                    sha384=5, sha512=6 };

enum SignatureAlgorithm { anonymous=0, rsa=1, dsa=2, ecdsa=3 };

struct SignatureAndHashAlgorithm {
    HashAlgorithm hash;
    SignatureAlgorithm signature;
};
                    
struct DigitallySigned {
    SignatureAndHashAlgorithm algorithm;
    opaque *signature;
};

/*
 * P_hash function. Section 5.
 *
 * Assuming the output is 80 bytes.
 */
ByteArray P_SHA256(const ByteArray& secret, const ByteArray& seed) {

    SHA256 sha256;
    
    ByteArray A0(seed);
    sha256.update(secret);
    sha256.update(A0);
    ByteArray A1(sha256.digest());
    sha256.reset();
    sha256.update(secret);
    sha256.update(A1);
    ByteArray A2(sha256.digest());
    sha256.reset();
    sha256.update(secret);
    sha256.update(A2);
    ByteArray A3(sha256.digest());

    ByteArray result;
    result.append(A1);
    result.append(A2);
    result.append(A3);
    return result.range(16, 80);

}

/*
 * Pseudorandom function. Section 5.
 */
ByteArray PRF(const ByteArray& secret, const ByteArray& label, const ByteArray& seed) {

    ByteArray ls;
    ls.append(label);
    ls.append(seed);
    return P_SHA256(secret, ls);

}

/*
 * Connection state values. Section 6.1
 */
enum ConnectionEnd { server, client };

enum PRFAlgorithm { tls_prf_sha256 };

enum BulkCipherAlgorithm { BCAnull, rc4, tdes, aes };

enum CipherType{ stream, block, aead };

enum MACAlgorithm { MAnull, hmac_md5, hmac_sha1, hmac_sha256,
                        hmac_sha384, hmac_sha512};

// This will be handled as a uint8_t value.
enum CompressionMethod { CMnull };

struct SecurityParameters {
    ConnectionEnd          entity;
    PRFAlgorithm           prf_algorithm;
    BulkCipherAlgorithm    bulk_cipher_algorithm;
    CipherType             cipher_type;
    uint8_t                enc_key_length;
    uint8_t                block_length;
    uint8_t                fixed_iv_length;
    uint8_t                record_iv_length;
    MACAlgorithm           mac_algorithm;
    uint8_t                mac_length;
    uint8_t                mac_key_length;
    CompressionMethod      compression_algorithm;
    opaque                 master_secret[48];
    opaque                 client_random[32];
    opaque                 server_random[32];
};

// Fragmentation. Section 6.2.1
struct ProtocolVersion {
    uint8_t major;
    uint8_t minor;
};

ProtocolVersion tls_1_2 = { 3, 3 };

// Handled as uint8_t value.
enum ContentType { change_cipher_spec=20, alert=21, handshake=22,
                                                application_data=23 };
struct TLSPlaintext {
    ContentType type;   // length > 0 where type = change_cipher_spec,
                        // alert, or handshake
    ProtocolVersion version;
    uint16 length;  // length < 2^14
    opaque *fragment;
};

// Section 6.2.1
struct TLSCompressed {
    ContentType type;   // length > 0 where type = change_cipher_spec,
                        // alert, or handshake
    ProtocolVersion version;
    uint16 length;  // length < 2^14
    opaque *fragment;
};

// Section 6.2.3
// S one of GenericStreamCipher, GenericBlockCipher, GenericAEADCipher
template <typename S>
struct TLSCiphertext {
    ContentType type;
    ProtocolVersion version;
    uint16 length;  // length < 2^14 + 2048
    S fragment;
};

// 6.2.3.1
// MAC is seq_num + TLSCompressed.type
//                  + TLSCompressed.version
//                  + TLSCompressed.length
//                  + TLSCompressed.fragment
//
// Key is MAC_write_key
// stream-ciphered
struct GenericStreamCipher {
    // TLSCompressed.length    
    opaque *content;
    // SecurityParameters.mac_length
    opaque *MAC;
};

// Section 6.3.2.2
struct GenericBlockCipher {
    // SecurityParameters.record_iv_length;
    opaque *IV;
    // block-ciphered
    struct {
        // TLSCompressed.length;
        opaque *content;
        // SecurityParameters.mac_length
        opaque *MAC;
        // GenericBlockCipher.padding_length
        uint8_t *padding;
        uint8_t padding_length;
    };
};

// Section 6.3.2.3
// additional_data = seq_num + TLSCompressed.type +
//                         TLSCompressed.version + TLSCompressed.length
struct GenericAEADCipher {
    // SecurityParameters.record_iv_length
    opaque *nonce_explicit;
    // aead-ciphered
    struct {
        // TLSCompressed.length
        opaque *content;
    };
};

// Alert protocol - Section 7.2
// Handled as uint8_t
enum Alert Level { warning=1, fatal=2 };

enum AlertDescription { close_notify=0, unexpected_message=10, bad_record_mac=20,
       decryption_failed_RESERVED=21, record_overflow=22, decompression_failure=30,
       handshake_failure=40, no_certificate_RESERVED=41, bad_certificate=42,
       unsupported_certificate=43, certificate_revoked=44, certificate_expired=45,
       certificate_unknown=46, illegal_parameter=47, unknown_ca=48,
       access_denied=49, decode_error=50, decrypt_error=51,
       export_restriction_RESERVED=60, protocol_version=70, insufficient_security=71,
       internal_error=80, user_canceled=90, no_renegotiation=100,
       unsupported_extension=110 };

struct Alert {
    AlertLevel level;
    AlertDescription description;
};


}
