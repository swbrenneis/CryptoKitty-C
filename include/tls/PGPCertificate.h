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
        void addUserID(const CKPGP::UserID& uid, const CKPGP::Signature& sig);
        CK::ByteArray encode();
        void encode(std::ostream& out);
        CKPGP::PublicKey *getPublicKey();
        void setPublicKey(CKPGP::PublicKey *pk);

    private:
        void decode(const CK::ByteArray& encoded);
        void decode(std::istream& in);
        uint32_t decodePGPLength(std::istream& in, CK::ByteArray& lBytes) const;

    private:
        CKPGP::PublicKey *publicKey;

        typedef std::deque<CKPGP::Signature> SignatureList;
        typedef SignatureList::iterator SigIter;
        typedef SignatureList::const_iterator SigConstIter;

        struct SignedID {
            CKPGP::UserID id;
            SignatureList sigs;
        };
        typedef std::deque<SignedID> UserIdList;
        typedef UserIdList::iterator IdIter;
        typedef UserIdList::const_iterator IdConstIter;
        UserIdList userIds;

        struct SignedAttr {
            CKPGP::UserAttribute attr;
            SignatureList sigs;
        };
        typedef std::deque<SignedAttr> UserAttrList;
        typedef UserAttrList::iterator AttrIter;
        typedef UserAttrList::const_iterator AttrConstIter;
        UserAttrList userAttributes;

        struct SignedSubkey {
            CKPGP::PublicSubkey sub;
            CKPGP::Signature sig;
        };
        typedef std::deque<SignedSubkey> SubkeyList;
        typedef SubkeyList::iterator SubIter;
        typedef SubkeyList::const_iterator SubConstIter;
        SubkeyList subKeys;

        SignatureList revocation;

};

}
#endif  // PGPCERTIFICATE_H_INCLUDED
