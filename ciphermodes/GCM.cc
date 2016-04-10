#include "ciphermodes/GCM.h"
#include "cipher/Cipher.h"
#include "data/Scalar64.h"
#include "data/Scalar32.h"
#include "data/BigInteger.h"
#include "exceptions/BadParameterException.h"
#include <deque>
#include <iostream>
#include <cmath>

namespace CK {

static const uint64_t P_MAX = 549755813632; // 2^39 - 256.
static const uint64_t A_MAX = 0xffffffffffffffff;
ByteArray GCM::R;
uint8_t GCM::t = 128;

GCM::GCM(Cipher *c, const ByteArray& iv)
: cipher(c),
  IV(iv) {

    if (cipher->blockSize() != 16) {
        throw BadParameterException("Invalid cipher block size");
    }

    //if (iv.getLength() * 8 != 96) {
    //    throw BadParameterException("Invalid IV size");
    //}

    if (R.getLength() == 0) {
        ByteArray r;
        ByteArray pad(15,0);
        r.append(0xe1);
        r.append(pad);
        R = expand(r);
    }

}

GCM::~GCM() {

    delete cipher;

}

/*
 * Shift the bit string one bit to the right. The MSB becomes 0;
 */
ByteArray GCM::bitShift(const ByteArray& string) const {

    if (string.getLength() != 128) {
        throw BadParameterException("Invalid string size for shift");
    }

    ByteArray shifted(string);
    // Perform the shift
    for (int i = 127; i > 0; --i) {
        shifted[i] = shifted[i-1];
    }
    shifted[0] = 0;

    return shifted;

}

/*
 * Expand the block into a bit string.
 */
ByteArray GCM::expand(const ByteArray& block) const {

    if (block.getLength() != 16) {
        throw BadParameterException("Invalid block size for expansion");
    }

    uint8_t bits[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
    // Expand the block.
    ByteArray string(128, 0);
    for (int i = 0; i < 128; ++i) {
        uint8_t byte = i / 8;
        if ((block[byte] & bits[i % 8]) != 0) {
            string[i] = 1;
        }
    }

    return string;

}

/*
 * Class decryption function.
 */
ByteArray GCM::decrypt(const ByteArray& ciphertext,
                                    const ByteArray& key) {

    return ByteArray(0);

}

/*
 * Class encryption function.
 */
ByteArray GCM::encrypt(const ByteArray& P, const ByteArray& K) {

    // l = (n - 1)128 + u
    int n = P.getLength() / 16;
    int u = P.getLength() % 16;
    if (u == 0) {
        u = 16;
        n--;
    }

    ByteArray H(cipher->encrypt(ByteArray(16, 0), K));

    ByteArray Y0;
    if (IV.getLength() == 12) {
        ByteArray ctr(4, 0);
        ctr[3] = 0x01;
        Y0.append(IV);
        Y0.append(ctr);
    }
    else {
        Y0 = GHASH(H, ByteArray(0), IV);
    }

    ByteArray Yi;           // Y(i)
    ByteArray Yi1(Y0);      // Y(i-1)
    ByteArray Pi;           // P(i)
    ByteArray Pn(P.range(P.getLength()-u, u));
    ByteArray Ci;           // C(i);
    ByteArray C;

    for (int i = 1; i <= n; ++i) {
        Yi = incr(Yi1);
        Pi = P.range((i-1)*16, 16);
        Ci = Pi ^ cipher->encrypt(Yi, K);
        C.append(Ci);
        Yi1 = Yi;
    }
    Yi = incr(Yi1);
    C.append(Pn ^ (cipher->encrypt(Yi, K)).range(0, u));

    T = GHASH(H, A, C);
    T = T ^ cipher->encrypt(Y0, K);

    return C;

}

/*
 * GCTR function. See NIST SP 800-38D, Section 6.5.
 * The constructed block arrays start at index 1 to conform with
 * the NIST algorithm specifications. The index is adjusted for
 * the Xi blocks since the plaintext array begins with index 0.
 *
ByteArray GCM::GCTR(const ByteArray& ICB, const ByteArray& X) const {

    if (ICB.getLength() != 16) {
        throw BadParameterException("Invalid counter block size");
    }

    if (X.getLength() == 0) {
        return X;
    }

    double lx = X.getLength() * 8;
    int n = ceil(lx / 128);
    std::deque<ByteArray> Xi;
    unsigned xnSize = X.getLength() % 16;
    if (xnSize == 0) {
        xnSize = 16;
    }
    ByteArray Xn(X.range(X.getLength() - xnSize, xnSize));
    unsigned pushed = xnSize;
    unsigned index = 0;
    while (pushed < X.getLength()) {
        ByteArray block(X.range(index, 16));
        Xi.push_back(block);
        pushed += 16;
        index += 16;
    }
    // Push an empty block to make the index work.
    Xi.push_front(ByteArray(0));
    std::deque<ByteArray> CB(n+1);  // Because the indices start at 1
    CB[1] = ICB;
    for (int i = 2; i <= n; ++i) {  // Create the incremented counter blocks
       CB[i] = incr(CB[i-1], 32);
    }
    std::deque<ByteArray> Y(n);
    for (int i = 1; i < n; ++i) {   // Blocks 1..n-1
        Y[i] = Xi[i] ^ cipher->encrypt(CB[i], K);
    }
    ByteArray CBn(cipher->encrypt(CB[n], K));
    CBn = CBn.range(0, xnSize);   // Get leftmost xnSize bytes
    ByteArray Yn(Xn ^ CBn);

    ByteArray ciphertext;
    for (unsigned i = 1; i < Y.size(); ++i) {
        ciphertext.append(Y[i]);
    }
    ciphertext.append(Yn);

    return ciphertext;

}*/

const ByteArray& GCM::getAuthTag() const {

    return T;

}

/*
 * GHASH function. See NIST SP 800-38D, section 6.4.
 * X must be an even multiple of 16 bytes. H is the subhash
 * key. Yi is always 128 bits.
 */
ByteArray GCM::GHASH(const ByteArray& H, const ByteArray& A,
                                        const ByteArray& C) const {

    int m = (A.getLength() / 16) + 1;
    int v = A.getLength() % 16;
    if (v == 0) {
        v = 16;
        m--;
    }
    int n = (C.getLength() / 16) + 1;
    int u = C.getLength() % 16;
    if (u == 0) {
        u = 16;
        n--;
    }

    ByteArray Xi1(16, 0);                       // X(i-1)
    ByteArray Xi;                               // X(i)
    ByteArray Ai;                               // A(i)
    ByteArray Am(A.range(A.getLength()-v, v));  // A(n)
    ByteArray Ci;                               // C(i)
    ByteArray Cn(C.range(C.getLength()-u, u));  // A(n)

    for (int i = 1; i <= m + n + 1; ++i) {
        if (i >= 1 && i <= m - 1) {
            Ai = A.range((i-1)*16, 16);
            Xi = multiply(Xi1 ^ Ai, H);
        }
        if (i == m) {
            ByteArray pad(16-v, 0);
            Am.append(pad);
            Xi = multiply(Xi1 ^ Am, H);
        }
        if (i >= m + 1 && i <= (m + n) - 1) {
            // ((i - (m + 1)) - 1)
            Ci = C.range((i-m-1)*16, 16);
            Xi = multiply(Xi1 ^ Ci, H);
        }
        if (i == m + n) {
            ByteArray pad(16-u, 0);
            Cn.append(pad);
            Xi = multiply(Xi1 ^ Cn, H);
        }
        if (i == m + n + 1) {
            ByteArray ac;
            Scalar64 al(A.getLength() * 8);
            ac.append(al.getEncoded(Scalar64::BIGENDIAN));
            Scalar64 cl(C.getLength() * 8);
            ac.append(cl.getEncoded(Scalar64::BIGENDIAN));
            Xi = multiply(Xi1 ^ ac, H);
        }

        Xi1 = Xi;
    }

    return Xi;

}

/*
 * Galois incr function. See NIST SP 800-38D, section 6.2.
 * Increments the rightmost s bits of X leaving the leftmost in
 * the bit string unchanged.
 */
ByteArray GCM::incr(const ByteArray& X) const {

    if (X.getLength() != 16) {
        throw BadParameterException("Illegal block size");
    }

    ByteArray fixed(X.range(0, 12));
    Scalar32 x(X.range(12, 4), Scalar32::BIGENDIAN);
    Scalar32 inc(x.getIntValue() + 1);
    fixed.append(inc.getEncoded(Scalar32::BIGENDIAN, Scalar32::UNSIGNED));

    return fixed;

}

/*
 * Galois multiplication function. See NIST SP 800-3D, Section 6.3.
 * X, Y, and Z are 128 bits.
 */
ByteArray GCM::multiply(const ByteArray& X, const ByteArray& Y) const {

    if (X.getLength() != 16 || Y.getLength() != 16) {
        throw BadParameterException("Invalid multiplicand or multiplier size");
    }

    /*ByteArray Z(128, 0);
    ByteArray V(expand(X));
    ByteArray y(expand(Y));

    for (int i = 0; i < 128; ++i) {
        if (y[i] == 1) {
            Z = Z ^ V;
        }
        if (V[127] == 0) {
            V = bitShift(V);
        }
        else {
            V = bitShift(V) ^ R;
        }
    }

    return pack(Z);*/

    ByteArray Z(16,0);
    ByteArray V(Y);

    uint8_t bits[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 8; ++j) {
            if ((X[0] && bits[7 - j]) != 0) {
                Z = Z ^ V;
            }
            if ((V[15] & 0x01) != 0) {
                shiftBlock(V);
                V[0] = V[0] ^ 0xe1;
            }
            else {
                shiftBlock(V);
            }
        }
    }

    return Z;

}

/*
 * Pack the string into a block.
 */
ByteArray GCM::pack(const ByteArray& string) const {

    if (string.getLength() != 128) {
        throw BadParameterException("Invalid string size for pack");
    }

    uint8_t bits[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
    // Pack the string
    ByteArray packed(16, 0);
    for (int i = 0; i < 128; ++i) {
        uint8_t byte = i / 8;
        if (string[i] == 1) {
            packed[byte] |= bits[i % 8];
        }
    }

    return packed;

}

void GCM::shiftBlock(ByteArray& block) const {

    Scalar32 be(block.range(12, 4), Scalar32::BIGENDIAN);
    uint32_t value = be.getUnsignedValue();
    value = value >> 1;
    if ((block[11] & 0x01) != 0) {
        value |= 0x80000000;
    }
    Scalar32 v(value, Scalar32::UNSIGNED);
    block.copy(12, v.getEncoded(Scalar32::BIGENDIAN, Scalar32::UNSIGNED), 0, 4);

    be = Scalar32(block.range(8, 4), Scalar32::BIGENDIAN);
    value = be.getUnsignedValue();
    value = value >> 1;
    if ((block[7] & 0x01) != 0) {
        value |= 0x80000000;
    }
    v = Scalar32(value, Scalar32::UNSIGNED);
    block.copy(8, v.getEncoded(Scalar32::BIGENDIAN, Scalar32::UNSIGNED), 0, 4);

    be = Scalar32(block.range(4, 4), Scalar32::BIGENDIAN);
    value = be.getUnsignedValue();
    value = value >> 1;
    if ((block[3] & 0x01) != 0) {
        value |= 0x80000000;
    }
    v = Scalar32(value, Scalar32::UNSIGNED);
    block.copy(4,v.getEncoded(Scalar32::BIGENDIAN, Scalar32::UNSIGNED), 0, 4);

    be = Scalar32(block.range(0, 4), Scalar32::BIGENDIAN);
    value = be.getUnsignedValue();
    value = value >> 1;
    v = Scalar32(value, Scalar32::UNSIGNED);
    block.copy(0, v.getEncoded(Scalar32::BIGENDIAN), 0, 4);

}

void GCM::setAuthData(const ByteArray& ad) {

    if (ad.getLength() * 8 > A_MAX) {
        throw BadParameterException("Invalid authentication tag");
    }

    A = ad;

}

void GCM::setAuthTag(const ByteArray& tag) {

    if (tag.getLength() * 8 != t) {
        throw BadParameterException("Invalid authentication tag");
    }

    T = tag;

}

}

