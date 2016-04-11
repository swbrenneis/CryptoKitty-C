#include "ciphermodes/GCM.h"
#include "cipher/Cipher.h"
#include "data/Unsigned64.h"
#include "data/Unsigned32.h"
#include "data/BigInteger.h"
#include "exceptions/BadParameterException.h"
#include "exceptions/AuthenticationException.h"
#include <deque>
#include <iostream>
#include <cmath>

        namespace CK {

        static const uint64_t P_MAX = 549755813632; // 2^39 - 256.
        static const uint64_t A_MAX = 0xffffffffffffffff;
        uint8_t GCM::t = 128;

        GCM::GCM(Cipher *c, const ByteArray& iv)
        : cipher(c),
          IV(iv) {

            if (cipher->blockSize() != 16) {
                throw BadParameterException("Invalid cipher block size");
            }

        }

        GCM::~GCM() {

            delete cipher;

        }

        /*
         * Class decryption function.
         */
        ByteArray GCM::decrypt(const ByteArray& C, const ByteArray& K) {

            // l = (n - 1)128 + u
            int n = C.getLength() / 16;
            int u = C.getLength() % 16;
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

            ByteArray Tp(GHASH(H, A, C));
            Tp = Tp ^ cipher->encrypt(Y0, K);
            if (T != Tp) {
                throw AuthenticationException("GCM AEAD failed authentication");
            }

            ByteArray Yi;           // Y(i)
            ByteArray Yi1(Y0);      // Y(i-1)
            ByteArray Ci;           // C(i)
            ByteArray Pi;           // C(i);
            ByteArray P;

            if (C.getLength() > 0) {
                for (int i = 1; i <= n; ++i) {
                    Yi = incr(Yi1);
                    Ci = C.range((i-1)*16, 16);
                    Pi = Ci ^ cipher->encrypt(Yi, K);
                    P.append(Pi);
                    Yi1 = Yi;
                }
                Yi = incr(Yi1);
                ByteArray Cn(C.range(C.getLength()-u, u));
                P.append(Cn ^ (cipher->encrypt(Yi, K)).range(0, u));
            }

            return P;

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
            ByteArray Ci;           // C(i);
            ByteArray C;

            if (P.getLength() > 0) {
                for (int i = 1; i <= n; ++i) {
                    Yi = incr(Yi1);
                    Pi = P.range((i-1)*16, 16);
                    Ci = Pi ^ cipher->encrypt(Yi, K);
                    C.append(Ci);
                    Yi1 = Yi;
                }
                Yi = incr(Yi1);
                ByteArray Pn(P.range(P.getLength()-u, u));
                C.append(Pn ^ (cipher->encrypt(Yi, K)).range(0, u));
            }

            T = GHASH(H, A, C);
            T = T ^ cipher->encrypt(Y0, K);

            return C;

        }

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

            if (H.getLength() != 16) {
                throw BadParameterException("Invalid hash sub-key");
            }

            int m = A.getLength() / 16;
            int v = A.getLength() % 16;
            if (v == 0) {
                v = 16;
                m--;
            }
            int n = C.getLength() / 16;
            int u = C.getLength() % 16;
            if (u == 0) {
                u = 16;
                n--;
            }

            ByteArray Xi1(16, 0);           // X(i-1)
            ByteArray Xi;                   // X(i)
            ByteArray Ai;                   // A(i)
            ByteArray Ci;                   // C(i)

            int i = 1; // For tracking Xi index. Debug only.
            for (int j = 0; j < m; ++j) {
                Ai = A.range(j * 16, 16);
                Xi = multiply(Xi1 ^ Ai, H);
                i++;
                Xi1 = Xi;
            }

            if (A.getLength() > 0) {
                ByteArray Am(A.range(A.getLength() - v, v));    // A(n)
                ByteArray pad(16-v, 0);
                Am.append(pad);
                Xi = multiply(Xi1 ^ Am, H);
                i++;
                Xi1 = Xi;
            }

            for (int j = 0; j < n; ++j) {
                Ci = C.range(j * 16, 16);
                Xi = multiply(Xi1 ^ Ci, H);
                i++;
                Xi1 = Xi;
            }

            if (C.getLength() > 0) {
                ByteArray Cn(C.range(C.getLength() - u, u));    // A(n)
                ByteArray pad(16-u, 0);
                Cn.append(pad);
                Xi = multiply(Xi1 ^ Cn, H);
                i++;
                Xi1 = Xi;
            }

            ByteArray ac;
            Unsigned64 al(A.getLength() * 8);
            ac.append(al.getEncoded(Unsigned64::BIGENDIAN));
            Unsigned64 cl(C.getLength() * 8);
            ac.append(cl.getEncoded(Unsigned64::BIGENDIAN));
    Xi = multiply(Xi1 ^ ac, H);

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
    Unsigned32 x(X.range(12, 4), Unsigned32::BIGENDIAN);
    Unsigned32 inc(x.getUnsignedValue() + 1);
    fixed.append(inc.getEncoded(Unsigned32::BIGENDIAN));

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

    ByteArray Z(16,0);
    ByteArray V(Y);

    //std:: cout << "X = " << X << std::endl
    //        << "Y = " << Y << std::endl << std::endl;
    uint8_t bits[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 8; ++j) {
    //    std::cout << "i = " << i << ", j = " << j << std::endl
    //            << "V = " << V << std::endl
    //            << "Z = " << Z << std::endl << std::endl;
            if ((X[i] & bits[7-j]) != 0) {
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

void GCM::shiftBlock(ByteArray& block) const {

    Unsigned32 be(block.range(12, 4), Unsigned32::BIGENDIAN);
    uint32_t value = be.getUnsignedValue();
    value = value >> 1;
    if ((block[11] & 0x01) != 0) {
        value |= 0x80000000;
    }
    Unsigned32 v(value);
    block.copy(12, v.getEncoded(Unsigned32::BIGENDIAN), 0, 4);

    be = Unsigned32(block.range(8, 4), Unsigned32::BIGENDIAN);
    value = be.getUnsignedValue();
    value = value >> 1;
    if ((block[7] & 0x01) != 0) {
        value |= 0x80000000;
    }
    v = Unsigned32(value);
    block.copy(8, v.getEncoded(Unsigned32::BIGENDIAN), 0, 4);

    be = Unsigned32(block.range(4, 4), Unsigned32::BIGENDIAN);
    value = be.getUnsignedValue();
    value = value >> 1;
    if ((block[3] & 0x01) != 0) {
        value |= 0x80000000;
    }
    v = Unsigned32(value);
    block.copy(4,v.getEncoded(Unsigned32::BIGENDIAN), 0, 4);

    be = Unsigned32(block.range(0, 4), Unsigned32::BIGENDIAN);
    value = be.getUnsignedValue();
    value = value >> 1;
    v = Unsigned32(value);
    block.copy(0, v.getEncoded(Unsigned32::BIGENDIAN), 0, 4);

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

