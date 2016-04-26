#include "tls/PGPCertificate.h"
#include "exceptions/tls/RecordException.h"
#include "data/Unsigned16.h"
#include "data/Unsigned32.h"

namespace CKTLS {

// TODO: Maybe copy on write semantics?
PGPCertificate::PGPCertificate()
: publicKey(0) {
}

PGPCertificate::PGPCertificate(const CK::ByteArray& encoded) {

    decode(encoded);

}

PGPCertificate::PGPCertificate(std::istream& in) {

    decode(in);

}

PGPCertificate::PGPCertificate(const PGPCertificate& other)
: publicKey(new CKPGP::PublicKey(*other.publicKey)),
  userIds(other.userIds),
  userAttributes(other.userAttributes),
  subKeys(other.subKeys),
  revocation(other.revocation) {
}

PGPCertificate::~PGPCertificate() {

    delete publicKey;

}

PGPCertificate& PGPCertificate::operator= (const PGPCertificate& other) {

    publicKey = new CKPGP::PublicKey(*other.publicKey);
    userIds = other.userIds;
    userAttributes = other.userAttributes;
    subKeys = other.subKeys;
    revocation = other.revocation;
    return *this;

}

void PGPCertificate::decode(const CK::ByteArray& encoded) {

    unsigned index = 0;
    CKPGP::Packet *packet = CKPGP::Packet::decodePacket(encoded);
    if (packet->getTag() != CKPGP::Packet::PUBLICKEY) {
        throw RecordException("Invalid certificate");
    }
    publicKey = dynamic_cast<CKPGP::PublicKey*>(packet);
    index += publicKey->getPacketLength();

    bool userSection = true;
    // Yuck.
    while (index < encoded.getLength()) {
        packet = CKPGP::Packet::decodePacket(encoded.range(index,
                                                        encoded.getLength() - index));
        index += packet->getPacketLength();
        if (packet->getTag() == CKPGP::Packet::USERID) {
            if (!userSection) {
                throw RecordException("Invalid certificate");
            }
            SignedID id;
            id.id = dynamic_cast<CKPGP::UserID*>(packet);
            bool signatures = true;
            while (index < encoded.getLength() && signatures) {
                //Peek at the packet before updating the index
                packet = CKPGP::Packet::decodePacket(encoded.range(index,
                                                            encoded.getLength() - index));
                if (packet->getTag() == CKPGP::Packet::SIGNATURE) {
                    index += packet->getPacketLength();
                    id.sigs.push_back(dynamic_cast<CKPGP::Signature*>(packet));
                }
                else {
                    signatures = false;
                }
            }
        }
        else if (packet->getTag() == CKPGP::Packet::USERATTRIBUTE) {
            if (!userSection) {
                throw RecordException("Invalid certificate");
            }
            SignedAttr attr;
            attr.attr = dynamic_cast<CKPGP::UserAttribute*>(packet);
            bool signatures = true;
            while (index < encoded.getLength() && signatures) {
                //Peek at the packet before updating the index
                packet = CKPGP::Packet::decodePacket(encoded.range(index,
                                                        encoded.getLength() - index));
                if (packet->getTag() == CKPGP::Packet::SIGNATURE) {
                    index += packet->getPacketLength();
                    attr.sigs.push_back(dynamic_cast<CKPGP::Signature*>(packet));
                }
                else {
                    signatures = false;
                }
            }
        }
        else if (packet->getTag() == CKPGP::Packet::PUBLICSUBKEY) {
            userSection = false;
            SignedSubkey sub;
            sub.sub = dynamic_cast<CKPGP::PublicSubkey*>(packet);
            packet = CKPGP::Packet::decodePacket(encoded.range(index, encoded.getLength() - index));
            index += packet->getPacketLength();
            sub.sig = dynamic_cast<CKPGP::Signature*>(packet);
            subKeys.push_back(sub);
        }
        else if (packet->getTag() == CKPGP::Packet::SIGNATURE) {
            userSection = false;
            revocation.push_back(dynamic_cast<CKPGP::Signature*>(packet));
        }
        else {
            throw RecordException("Invalid certificate");
        }
    }

}

void PGPCertificate::decode(std::istream& in) {

    CK::ByteArray pbuf;
    getPacket(in, pbuf);
    CKPGP::Packet *packet = CKPGP::Packet::decodePacket(pbuf);
    if (packet->getTag() != CKPGP::Packet::PUBLICKEY) {
        throw RecordException("Invalid certificate");
    }
    publicKey = dynamic_cast<CKPGP::PublicKey*>(packet);

    bool userSection = true;
    // Yuck.
    while (in.good()) {
        pbuf.clear();
        getPacket(in, pbuf);
        packet = CKPGP::Packet::decodePacket(CK::ByteArray(pbuf));
        if (packet->getTag() == CKPGP::Packet::USERID) {
            if (!userSection) {
                throw RecordException("Invalid certificate");
            }
            SignedID id;
            id.id = dynamic_cast<CKPGP::UserID*>(packet);
            bool signatures = true;
            while (in.good() && signatures) {
                //Peek at the packet before updating the index
                std::streampos pos = in.tellg();
                pbuf.clear();
                getPacket(in, pbuf);
                packet = CKPGP::Packet::decodePacket(pbuf);
                if (packet->getTag() == CKPGP::Packet::SIGNATURE) {
                    id.sigs.push_back(dynamic_cast<CKPGP::Signature*>(packet));
                }
                else {
                    in.seekg(pos);
                    signatures = false;
                }
            }
        }
        else if (packet->getTag() == CKPGP::Packet::USERATTRIBUTE) {
            if (!userSection) {
                throw RecordException("Invalid certificate");
            }
            SignedAttr attr;
            attr.attr = dynamic_cast<CKPGP::UserAttribute*>(packet);
            bool signatures = true;
            while (in.good() && signatures) {
                //Peek at the packet before updating the index
                std::streampos pos = in.tellg();
                pbuf.clear();
                getPacket(in, pbuf);
                packet = CKPGP::Packet::decodePacket(pbuf);
                if (packet->getTag() == CKPGP::Packet::SIGNATURE) {
                    attr.sigs.push_back(dynamic_cast<CKPGP::Signature*>(packet));
                }
                else {
                    in.seekg(pos);
                    signatures = false;
                }
            }
        }
        else if (packet->getTag() == CKPGP::Packet::PUBLICSUBKEY) {
            userSection = false;
            SignedSubkey sub;
            sub.sub = dynamic_cast<CKPGP::PublicSubkey*>(packet);
            pbuf.clear();
            getPacket(in, pbuf);
            packet = CKPGP::Packet::decodePacket(pbuf);
            sub.sig = dynamic_cast<CKPGP::Signature*>(packet);
            subKeys.push_back(sub);
        }
        else if (packet->getTag() == CKPGP::Packet::SIGNATURE) {
            userSection = false;
            revocation.push_back(dynamic_cast<CKPGP::Signature*>(packet));
        }
        else {
            throw RecordException("Invalid certificate");
        }
    }

}

uint32_t PGPCertificate::decodePGPLength(std::istream& in, CK::ByteArray& lBytes) const {

    char octets[5];
    uint8_t *ubuf = reinterpret_cast<uint8_t*>(octets);
    in.get(octets[0]);
    lBytes.append(ubuf[0]);
    if (octets[0] < 192) {
        return ubuf[0];
    }
    else if (octets[0] == 0xff) {
        in.get(octets, 4);
        lBytes.append(ubuf, 4);
        CK::Unsigned32 len(lBytes.range(1, 4), CK::Unsigned32::BIGENDIAN);
        return len.getUnsignedValue();
    }
    else {
        in.get(octets[0]);
        lBytes.append(ubuf[0]);
        CK::Unsigned16 len(lBytes, CK::Unsigned16::BIGENDIAN);
        return len.getUnsignedValue();
    }

}

CK::ByteArray PGPCertificate::encode() const {

    // PGP structures are a series of self-contained packets.
    CK::ByteArray encoded;
    encoded.append(publicKey->getEncoded());
    if (encoded.getLength() == 0) {
        throw RecordException("Invalid public key");
    }

    // User IDs. May be unsigned.
    if (userIds.size() == 0) {
        throw RecordException("No associated user ids");
    }
    for (IdConstIter it = userIds.begin(); it != userIds.end(); ++it) {
        encoded.append(it->id->getEncoded());
        for (SigConstIter sit = it->sigs.begin(); sit != it->sigs.end(); ++sit) {
            encoded.append((*sit)->getEncoded());
        }
    }

    // User attributes. May be unsigned.
    for (AttrConstIter it = userAttributes.begin(); it != userAttributes.end(); ++it) {
        encoded.append(it->attr->getEncoded());
        for (SigConstIter sit = it->sigs.begin(); sit != it->sigs.end(); ++sit) {
            encoded.append((*sit)->getEncoded());
        }
    }

    // Subkeys. Must be signed.
    for (SubConstIter it = subKeys.begin(); it != subKeys.end(); ++it) {
        encoded.append(it->sub->getEncoded());
        encoded.append(it->sig->getEncoded());
    }

    // Revocation signatures.
    for (SigConstIter it = revocation.begin(); it != revocation.end(); ++it) {
        encoded.append((*it)->getEncoded());
    }

    return encoded;

}

void PGPCertificate::getPacket(std::istream& in, CK::ByteArray& pbuf) const {

    char buffer[65536];
    uint8_t *ubuf = reinterpret_cast<uint8_t*>(buffer);
    in.get(buffer[0]);
    pbuf.append(ubuf[0]);
    CK::ByteArray lBytes;
    uint32_t len = decodePGPLength(in, lBytes);
    pbuf.append(lBytes);
    in.get(buffer, len);
    pbuf.append(ubuf, len);

}

void PGPCertificate::setPublicKey(CKPGP::PublicKey *pk) {

    delete publicKey;
    publicKey = pk;

}

}
