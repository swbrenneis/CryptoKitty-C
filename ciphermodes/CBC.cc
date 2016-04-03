#include "ciphermodes/CBC.h"
#include "cipher/Cipher.h"
#include "exceptions/BadParameterException.h"
#include <deque>

namespace CK {

CBC::CBC(Cipher *c, const ByteArray& i)
: cipher(c),
  iv(i) {

    blockSize = cipher->blockSize();
    if (iv.getLength() != blockSize) {
        throw BadParameterException("CBC Invalid IV");
    }

}

CBC::~CBC() {
        
    delete cipher;

}

ByteArray CBC::decrypt(const ByteArray& iv, const ByteArray& block,
                                            const ByteArray& key) const {

    ByteArray textblock(cipher->decrypt(block, key));
    return textblock ^ iv;

}

ByteArray CBC::encrypt(const ByteArray& iv, const ByteArray& block,
                                            const ByteArray& key) const {

    return cipher->encrypt(iv ^ block, key);

}

ByteArray CBC::decrypt(const ByteArray& ciphertext, const ByteArray& key) {

    ByteArray plaintext;
    ByteArray padded;
    unsigned textSize = ciphertext.getLength();
    unsigned blockOffset = 0;
    ByteArray cblock;
    if (textSize % blockSize != 0) {
        while (textSize > blockSize) {
            cblock = ciphertext.range(blockOffset, blockSize);
            textSize -= blockSize;
            blockOffset += blockSize;
        }
        // Decrypt second to last block.
        ByteArray padBlock(cipher->decrypt(cblock, key));
        // Get padding bits.
        ByteArray padBytes(padBlock.range(textSize, blockSize - textSize));
        padded = ciphertext;
        // Pad the original ciphertext.
        padded.append(padBytes);
        // Extract the last 2 blocks.
        ByteArray b1(padded.range(padded.getLength()-(blockSize*2), blockSize));
        ByteArray b2(padded.range(padded.getLength()-(blockSize), blockSize));
        // Swap blocks.
        padded = padded.range(0, padded.getLength()-(blockSize*2));
        padded.append(b2);
        padded.append(b1);
    }
    else {
        padded = ciphertext;
    }
    textSize = padded.getLength();
    blockOffset = 0;
    ByteArray input(iv);
    while (textSize > 0) {
        ByteArray cipherblock(padded.range(blockOffset, blockSize));
        ByteArray plainblock(decrypt(input, cipherblock, key));
        plaintext.append(plainblock);
        input = cipherblock;
        blockOffset += blockSize;
        textSize -= blockSize;
    }
    return plaintext.range(0, ciphertext.getLength());

}

ByteArray CBC::encrypt(const ByteArray& plaintext, const ByteArray& key) {

    ByteArray ciphertext;
    ByteArray padded(plaintext);
    // plaintext is padded. Need to steal cipherbits
    bool steal = padded.getLength() % blockSize != 0;
    while (padded.getLength() % blockSize != 0) {
        padded.append(0);
    }
    unsigned textLength = padded.getLength();
    ByteArray input = iv;
    ByteArray cipherblock;
    std::deque<ByteArray> blocks;
    unsigned blockStart = 0;
    while (textLength > 0) {
        ByteArray plainblock(padded.range(blockStart, blockSize));
        ByteArray cipherblock(encrypt(input, plainblock, key));
        input = cipherblock;
        blocks.push_back(cipherblock);
        blockStart += blockSize;
        textLength -= blockSize;
    }

    if (steal) {
        // Swap last two blocks
        ByteArray cn = blocks.back();
        blocks.pop_back();
        ByteArray cn1 = blocks.back();
        blocks.pop_back();
        blocks.push_back(cn);
        blocks.push_back(cn1);
    }

    while (blocks.size() > 0) {
        ciphertext.append(blocks.front());
        blocks.pop_front();
    }

    return ciphertext.range(0, plaintext.getLength());

}

}
