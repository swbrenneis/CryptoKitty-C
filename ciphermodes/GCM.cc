#include "ciphermodes/GCM.h"
#include "cipher/Cipher.h"
#include "data/Scalar64.h"
#include "data/BigInteger.h"
#include "exceptions/BadParameterException.h"
#include <deque>
#include <cmath>

namespace CK {

static const uint64_t P_MAX = 549755813632; // 2^39 - 256.
static const uint64_t A_MAX = 0xffffffffffffffff;
static const uint64_t IV_MAX = 0xffffffffffffffff;
BigInteger GCM::R(0L);

GCM::GCM(Cipher *c, const ByteArray& iv)
: cipher(c),
  IV(iv) {

    if (cipher->blockSize() != 16) {
        throw BadParameterException("Invalid cipher block size");
    }

    if (R == 0L) {
        R = 0xe1;
        R = R << 120;
    }

}

GCM::~GCM() {

    delete cipher;

}

/*
 * Class decryption function.
 */
ByteArray GCM::decrypt(const ByteArray& ciphertext,
                                    const ByteArray& key) {

    K = key;
    ByteArray nothing;
    return nothing;

}

/*
 * Class encryption function.
 */
ByteArray GCM::encrypt(const ByteArray& plaintext,
                                    const ByteArray& key) {

    K = key;
    return GCM_AE(plaintext);

}

/*
 * GCM authenticated encryption algorithm. See NIST SP 800-3D,
 * Section 7.1
 * The IV and AD values must be preset.
 */
ByteArray GCM::GCM_AE(const ByteArray& P) {

    if (IV.getLength() == 0 || AD.getLength() == 0) {
        throw BadParameterException("Invalid IV or AD value");
    }

    if (P.getLength() > P_MAX / 8) {
        throw BadParameterException("Plaintext too long.");
    }

    ByteArray null(16, 0);
    ByteArray h(cipher->encrypt(null, K));
    BigInteger H(h, BigInteger::LITTLEENDIAN);
    // Normalize IV to 128 bits.
    BigInteger iv(IV, BigInteger::LITTLEENDIAN);
    unsigned ivLen = iv.bitLength();
    ByteArray J0;
    if (ivLen == 96) {
        ByteArray pad(4, 0);
        pad[0] = 1;
        J0 = IV;
        J0.append(pad);
    }
    else {
        double ivl = ivLen;
        int s = (128 * ceil(ivl / 128)) - ivLen;
        ByteArray j(IV);
        j = j << s + 64;
        Scalar64 iv64(ivLen);
        j.append(iv64.encode(Scalar64::LITTLEENDIAN));
        J0 = GHASH(j, H);
    }

    BigInteger ji(J0, BigInteger::LITTLEENDIAN);
    ji = increment(ji, 32);
    ByteArray C(GCTR(ji.encode(BigInteger::LITTLEENDIAN), P));

    BigInteger c(C, BigInteger::LITTLEENDIAN);
    double lc = c.bitLength();
    int lci  = c.bitLength();
    int u = (128 * ceil(lc / 128)) - lci;
    BigInteger a(AD, BigInteger::LITTLEENDIAN);
    double la = a.bitLength();
    int lai = a.bitLength();
    int v = (128 * ceil(la / 128)) - lai;

    ByteArray s(AD);
    s = s << v;
    s.append(C);
    s = s << u;
    Scalar64 al(lai);
    s.append(al.encode(Scalar64::LITTLEENDIAN));
    Scalar64 cl(lci);
    s.append(cl.encode(Scalar64::LITTLEENDIAN));
    ByteArray S(GHASH(s, H));
    ByteArray t(GCTR(J0, S));
    int tlen = K.getLength();
    T = t.range(t.getLength()-tlen, tlen);

    return C;

}

/*
 * GCTR function. See NIST SP 800-38D, Section 6.5.
 * The constructed block arrays start at index 1 to conform with
 * the NIST algorithm specifications. The index is adjusted for
 * the Xi blocks since the plaintext array begins with index 0.
 */
ByteArray GCM::GCTR(const ByteArray& ICB, const ByteArray& X) const {

    if (X.getLength() == 0) {
        return X;
    }

    double lx = X.getLength() * 8;
    int n = ceil(lx / 128);
    // Last full or partial block
    unsigned bs = X.getLength() % 16;
    if (bs == 0) {
        bs = 16;
    }
    ByteArray Xn = X.range((n-1)*16, bs);
    std::deque<ByteArray> CB(n+1);
    CB[1] = ICB;
    for (int i = 2; i <= n; ++i) {
       BigInteger cbi1(CB[i-1], BigInteger::LITTLEENDIAN);
       CB[i] = increment(cbi1, 32).encode(BigInteger::LITTLEENDIAN);
    }
    std::deque<ByteArray> Y(n-1);
    for (int i = 1; i < n; ++i) {
        ByteArray Xi(X.range((i-1)*16, 16));
        Y[i] = Xi ^ cipher->encrypt(CB[i], K);
    }
    unsigned xnLen = Xn.getLength();
    ByteArray CBn(cipher->encrypt(CB[n], K));
    CBn = CBn.range(16-xnLen, xnLen);
    ByteArray Yn(Xn ^ CBn);

    ByteArray ciphertext(Y[1]);
    for (unsigned i = 2; i < Y.size(); ++i) {
        ciphertext.append(Y[i]);
    }
    ciphertext.append(Yn);

    return ciphertext;

}

const ByteArray& GCM::getAuthTag() const {

    return T;

}

/*
 * GHASH function. See NIST SP 800-38D, section 6.4.
 * X must be an even multiple of 16 bytes. H is the subhash
 * key. Yi is always 128 bits.
 */
ByteArray GCM::GHASH(const ByteArray& X, const BigInteger& H) const {

    if (X.getLength() % 16 != 0) {
        throw BadParameterException("Invalid X input to GHASH.");
    }

    unsigned m = X.getLength() / 16;
    ByteArray Yi1(16, 0);   // Y(i-1)
    ByteArray Yi;           // Y(i)

    for (unsigned i = 0; i < m; ++i) {
        ByteArray Xi = X.range(i*16, 16);
        BigInteger Yt(Xi ^ Yi1, BigInteger::LITTLEENDIAN);
        Yt = multiply(Yt, H);
        Yi = Yt.encode(BigInteger::LITTLEENDIAN);
        if (Yi.getLength() < 16) {
            ByteArray pad(16 - Yi.getLength(), 0);
            pad.append(Yi);
            Yi = pad;
        }
        Yi1 = Yi;
    }

    return Yi;

}

/*
 * Galois increment function. See NIST SP 800-38D, section 6.2.
 * Increments the rightmost s bits of X leaving the leftmost in
 * the bit string unchanged.
 */
BigInteger GCM::increment(const BigInteger& X, int s) const {

    BigInteger lmask(0L);
    for (int n = 0; n < s; ++n) {
        lmask = lmask << 1;
        lmask = lmask | 1;
    }
    BigInteger umask(~lmask);
    return ((X + 1) & lmask) | (X & umask);

}

/*
 * Galois multiplication function. See NIST SP 800-3D, Section 6.3.
 * X, Y, and Z are 128 bits.
 */
BigInteger GCM::multiply(const BigInteger& X, const BigInteger& Y) const {

    BigInteger Zi(0L);   // Z(i)
    BigInteger Zi1;     // Z(i+1)
    BigInteger Vi(Y);   // V(i)
    BigInteger Vi1;     // V(i+1)

    for (int i = 0; i < 128; ++i) {
        if (X.testBit(i)) {
            Zi1 = Zi ^ Vi;
        }
        else {
            Zi1 = Zi;
        }
        if (Vi.testBit(1)) {
            Vi1 = (Vi >> 1) ^ R;
        }
        else {
            Vi1 = Vi >> 1;
        }
        Zi = Zi1;
        Vi = Vi1;
    }

    return Zi;

}

void GCM::setAuthData(const ByteArray& ad) {

    AD = ad;

}

void GCM::setAuthTag(const ByteArray& tag) {

    T = tag;

}

}

