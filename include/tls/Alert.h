#ifndef ALERT_H_INCLUDED
#define ALERT_H_INCLUDED

#include "tls/Plaintext.h"
#include "data/ByteArray.h"

namespace CKTLS {

class Alert : public Plaintext {

    public:
        enum AlertDescription { close_notify=0, unexpected_message=10,
                                bad_record_mac=20, decryption_failed_RESERVED=21,
                                record_overflow=22, decompression_failure=30,
                                handshake_failure=40, no_certificate_RESERVED=41,
                                bad_certificate=42, unsupported_certificate=43,
                                certificate_revoked=44, certificate_expired=45,
                                certificate_unknown=46, illegal_parameter=47,
                                unknown_ca=48, access_denied=49, decode_error=50,
                                decrypt_error=51, export_restriction_RESERVED=60,
                                protocol_version=70, insufficient_security=71,
                                internal_error=80, user_canceled=90,
                                no_renegotiation=100, unsupported_extension=110 };

    public:
        Alert(AlertDescription d, bool f = true);
        ~Alert();
        Alert(const Alert& other);
        Alert& operator=(const Alert& other);

    public:
        void decode(const CK::ByteArray& encoded);
        CK::ByteArray encode();
        AlertDescription getDescription() const;
        bool isFatal() const;

    private:
        enum AlertLevel{ warning=1, fatal=2 };

        AlertDescription desc;
        AlertLevel level;

};

}

#endif  // ALERT_H_INCLUDED
