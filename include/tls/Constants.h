#ifndef CONSTANTS_H_INCLUDED
#define CONSTANTS_H_INCLUDED

namespace CKTLS {

enum HandshakeType { hello_request=0, client_hello=1,
                server_hello=2, certificate=11, server_key_exchange=12,
                certificate_request=13, server_hello_done=14,
                certificate_verify=15, client_key_exchange=16,
                finished=20 };

enum ConnectionEnd { server, client };

enum PRFAlgorithm { tls_prf_sha256 };

enum BulkCipherAlgorithm { bca_null, rc4, tdes, aes };

enum CipherType { stream, block, aead };

enum MACAlgorithm { mac_null, hmac_md5, hmac_sha1, hmac_sha256,
                           hmac_sha384, hmac_sha512};

enum CompressionMethod{ cm_null=0 };

enum HashAlgorithm { none=0, md5=1, sha1=2, sha224=3, sha256=4, sha384=5,
                        sha512=6 } ;

enum SignatureAlgorithm { anonymous=0, rsa=1, dsa=2, ecdsa=3 };

enum KeyExchangeAlgorithm { dhe_dss, dhe_rsa, dh_anon, rsa_ke, dh_dss, dh_rsa,
                        ec_diffie_hellman };

enum ECCurveType { explicit_prime=1, explicit_char2=2, named_curve=3 };

enum ECBasisType { ec_basis_trinomial, ec_basis_pentanomial };

enum NamedCurve { sect163k1=1, sect163r1=2, sect163r2=3, sect193r1=4,
                    sect193r2=5, sect233k1=6, sect233r1=7, sect239k1=8,
                    sect283k1=9, sect283r1=10, sect409k1=11, sect409r1=12,
                    sect571k1=13, sect571r1=14, secp160k1=15, secp160r1=16,
                    secp160r2=17, secp192k1=18, secp192r1=19, secp224k1=20,
                    secp224r1=21, secp256k1=22, secp256r1=23, secp384r1=24,
                    secp521r1=25, arbitrary_explicit_prime_curves=0xFF01,
                    arbitrary_explicit_char2_curves=0xFF02 };

enum CertificateType { x_509=0, openpgp=1 };

}

#endif  // CONSTANTS_H_INCLUDED
