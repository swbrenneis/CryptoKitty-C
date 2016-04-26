#ifndef PGPCERTIFICATE_H_INCLUDED
#define PGPCERTIFICATE_H_INCLUDED

#include "data/ByteArray.h"
#include "openpgp/packet/PublicKey.h"
#include "openpgp/packet/PublicSubkey.h"
#include "openpgp/packet/Signature.h"
#include "openpgp/packet/UserID.h"
#include "openpgp/packet/UserAttribute.h"
#include <iostream>

namespace CKTLS {

/*
 * See RFC 6019 Section 3.3 and RFC 4880 Section 11.1
 */
class PGPCertificate {

    public:
        PGPCertificate();
        PGPCertificate(const CK::ByteArray& encoded);
        PGPCertificate(std::istream& in);
        ~PGPCertificate();

    public:
        PGPCertificate(const PGPCertificate& other);
        PGPCertificate& operator= (const PGPCertificate& other);

    public:
        typedef std::deque<CKPGP::Signature*> SignatureList;
        typedef SignatureList::const_iterator SigConstIter;

    public:
        void addUserID(CKPGP::UserID* uid, const SignatureList& sigs);
        CK::ByteArray encode() const;
        void encode(std::ostream& out);
        void setPublicKey(CKPGP::PublicKey *pk);

    private:
        void decode(const CK::ByteArray& encoded);
        void decode(std::istream& in);
        uint32_t decodePGPLength(std::istream& in, CK::ByteArray& lBytes) const;
        void getPacket(std::istream& in, CK::ByteArray& pbuf) const;

    private:
        CKPGP::PublicKey *publicKey;

        struct SignedID {
            CKPGP::UserID *id;
            SignatureList sigs;
            ~SignedID() {
                delete id;
                while (sigs.size() > 0) {
                    delete sigs.front();
                    sigs.pop_front();
                }
            }
        };
        typedef std::deque<SignedID> UserIdList;
        typedef UserIdList::const_iterator IdConstIter;
        UserIdList userIds;

        struct SignedAttr {
            CKPGP::UserAttribute *attr;
            SignatureList sigs;
            ~SignedAttr() {
                delete attr;
                while (sigs.size() > 0) {
                    delete sigs.front();
                    sigs.pop_front();
                }
            }
        };
        typedef std::deque<SignedAttr> UserAttrList;
        typedef UserAttrList::const_iterator AttrConstIter;
        UserAttrList userAttributes;

        struct SignedSubkey {
            CKPGP::PublicSubkey *sub;
            CKPGP::Signature *sig;
            ~SignedSubkey() {
                delete sub;
                delete sig;
            }
        };
        typedef std::deque<SignedSubkey> SubkeyList;
        typedef SubkeyList::const_iterator SubConstIter;
        SubkeyList subKeys;

        SignatureList revocation;

};

}
#endif  // PGPCERTIFICATE_H_INCLUDED
