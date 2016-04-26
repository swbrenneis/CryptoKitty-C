#include "ciphermodes/CTR.h"
#include "cipher/Cipher.h"
#include "exceptions/BadParameterException.h"
#include "data/Unsigned64.h"
#include <cmath>

namespace CK {

CTR::CTR(Cipher *c, const ByteArray& n) {

    if (n.getLength() != c->blockSize() - 8) {
        throw BadParameterException("Invalid nonce size");
    }

    cipher = c;
    counter = n;
    ByteArray ctr(8,0);
    ctr[7] = 1;
    counter.append(ctr);

}

CTR::~CTR() {

    delete cipher;

}

ByteArray CTR::decrypt(const ByteArray& ciphertext, const ByteArray& key) {

    ByteArray P;

    double cs = ciphertext.getLength();
    uint32_t blockSize = cipher->blockSize();
    uint32_t blockCount = ceil(cs / blockSize);

    for (unsigned i = 0; i < blockCount; ++i) {
        uint32_t index = i * blockSize;
        incrementCounter();
        ByteArray pBlock(cipher->encrypt(counter, key));
        if (index + blockSize < ciphertext.getLength()) { // Whole block
            P.append(pBlock ^ ciphertext.range(index, blockSize));
        }
        else {          // Partial block, xor with encrypted counter LSB
            ByteArray partial(ciphertext.range(index, ciphertext.getLength() - index));
            ByteArray pctr(pBlock.range(0, partial.getLength()));
            P.append(partial ^ pctr);
        }
    }

    return P;

}

ByteArray CTR::encrypt(const ByteArray& plaintext, const ByteArray& key) {

    ByteArray C;

    double ps = plaintext.getLength();
    uint32_t blockSize = cipher->blockSize();
    uint32_t blockCount = ceil(ps / blockSize);

    for (unsigned i = 0; i < blockCount; ++i) {
        uint32_t index = i * blockSize;
        incrementCounter();
        ByteArray cBlock(cipher->encrypt(counter, key));
        if (index + blockSize < plaintext.getLength()) { // Whole block
            C.append(cBlock ^ plaintext.range(index, blockSize));
        }
        else {          // Partial block, xor with encrypted counter LSB
            ByteArray partial(plaintext.range(index, plaintext.getLength() - index));
            ByteArray pctr(cBlock.range(0, partial.getLength()));
            C.append(partial ^ pctr);
        }
    }

    return C;

}

void CTR::incrementCounter() {

    ByteArray nonce(counter.range(0, counter.getLength() - 4));
    Unsigned64 ctr(counter.range(nonce.getLength(), 4));
    counter.clear();
    ctr.setValue(ctr.getUnsignedValue() + 1);
    counter.append(nonce);
    counter.append(ctr.getEncoded(Unsigned64::BIGENDIAN));

}

}

