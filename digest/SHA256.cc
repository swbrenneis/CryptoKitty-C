#include "digest/SHA256.h"
#include "data/ByteArray.h"
#include "data/Scalar32.h"
#include "data/Scalar64.h"
#include <string.h>
#include <climits>

namespace CK {

// Static initializers
const unsigned SHA256::H1 = 0x6a09e667;
const unsigned SHA256::H2 = 0xbb67ae85;
const unsigned SHA256::H3 = 0x3c6ef372;
const unsigned SHA256::H4 = 0xa54ff53a;
const unsigned SHA256::H5 = 0x510e527f;
const unsigned SHA256::H6 = 0x9b05688c;
const unsigned SHA256::H7 = 0x1f83d9ab;
const unsigned SHA256::H8 = 0x5be0cd19;
const unsigned SHA256::K[] =
        { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
          0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
          0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
          0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
          0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
          0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
          0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
          0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
const unsigned char DERbytes[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 
                                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                                    0x00, 0x04, 0x20 };
const ByteArray DER(DERbytes, 19);

SHA256::SHA256(){
}

SHA256::~SHA256() {
}

/*
 * Ch(X, Y, Z) = (X ∧ Y ) ⊕ (X ∧ Z)
 *                          (~X)
 *   No corresponding X bar character
 */
unsigned SHA256::Ch(unsigned x, unsigned y, unsigned z) {

    return (x & y) ^ ((~x) & z);
            
}

/*
 * Decompose the message into 64 32 bit blocks.
 *
 * Split the message into 16 32 bit blocks by concatenating bytes.
 *
 * Generate 48 32 bit blocks with this formula.
 *
 * W(i) = σ1(W(i−2)) + W(i−7) + σ0(W(i−15)) + W(i−16), 17 ≤ i ≤ 64
 */
unsigned *SHA256::decompose(unsigned char *chunks) {

    unsigned *w = new unsigned[64];

    for (int j = 0; j < 16; ++j) {
        int i = j * 4;
        w[j] = chunks[i];
        w[j] = w[j] << 8;
        w[j] |= chunks[i+1];
        w[j] = w[j] << 8;
        w[j] |= chunks[i+2];
        w[j] = w[j] << 8;
        w[j] |= chunks[i+3];
    }

    for (int j = 16; j < 64; ++j) {
        w[j] = sigma1(w[j-2]) + w[j-7] + sigma0(w[j-15]) + w[j-16];
    }

    return w;

}

ByteArray SHA256::finalize(const ByteArray& in) {

    // Pad the message to an even multiple of 512 bits.
    ByteArray context(pad(in));

    // Split the message up into 512 bit chunks.
    long n = context.getLength() / 64;
    // We need the chunk array to begin at index 1 so the indexing
    // works out below.
    unsigned char chunks[n+1][64];
    long ci = 0;
    unsigned char *cArray = context.asArray();
    for (long i = 1; i <= n; i++) {
        memcpy(chunks[i], cArray+ci, 64);
        ci += 64;
    }

    // Set the initial hash seeds
    unsigned h1[n + 1];
    h1[0] = H1;
    unsigned h2[n + 1];
    h2[0] = H2;
    unsigned h3[n + 1];
    h3[0] = H3;
    unsigned h4[n + 1];
    h4[0] = H4;
    unsigned h5[n + 1];
    h5[0] = H5;
    unsigned h6[n + 1];
    h6[0] = H6;
    unsigned h7[n + 1];
    h7[0] = H7;
    unsigned h8[n + 1];
    h8[0] = H8;

    unsigned *w;
    // Process chunks.
    for (long i = 1; i <= n; ++i) {
        unsigned a = h1[i-1];
        unsigned b = h2[i-1];
        unsigned c = h3[i-1];
        unsigned d = h4[i-1];
        unsigned e = h5[i-1];
        unsigned f = h6[i-1];
        unsigned g = h7[i-1];
        unsigned h = h8[i-1];

        w = decompose(chunks[i]);

        for (int j = 0; j < 64; ++j) {

            unsigned T1 = h + Sigma1(e) + Ch(e, f, g) + K[j] + w[j];
            unsigned T2 = Sigma0(a) + Maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;

        }

        h1[i] = h1[i-1] + a;
        h2[i] = h2[i-1] + b;
        h3[i] = h3[i-1] + c;
        h4[i] = h4[i-1] + d;
        h5[i] = h5[i-1] + e;
        h6[i] = h6[i-1] + f;
        h7[i] = h7[i-1] + g;
        h8[i] = h8[i-1] + h;

    }

    delete[] w;

    ByteArray d;

    ByteArray encoded =
        Scalar32(h1[n]).getEncoded(Scalar32::BIGENDIAN); 
    d.append(encoded);
    encoded = Scalar32(h2[n]).getEncoded(Scalar32::BIGENDIAN); 
    d.append(encoded);
    encoded = Scalar32(h3[n]).getEncoded(Scalar32::BIGENDIAN); 
    d.append(encoded);
    encoded = Scalar32(h4[n]).getEncoded(Scalar32::BIGENDIAN); 
    d.append(encoded);
    encoded = Scalar32(h5[n]).getEncoded(Scalar32::BIGENDIAN); 
    d.append(encoded);
    encoded = Scalar32(h6[n]).getEncoded(Scalar32::BIGENDIAN); 
    d.append(encoded);
    encoded = Scalar32(h7[n]).getEncoded(Scalar32::BIGENDIAN); 
    d.append(encoded);
    encoded = Scalar32(h8[n]).getEncoded(Scalar32::BIGENDIAN); 
    d.append(encoded);

    return d;

}

/*
 * Return the ASN.1 encoding identifier
 */
const ByteArray& SHA256::getDER() const {

    return DER;

}

/*
 * Maj(X, Y, Z) = (X ∧ Y ) ⊕ (X ∧ Z) ⊕ (Y ∧ Z)
 */
unsigned SHA256::Maj(unsigned x, unsigned y, unsigned z) {

    return (x & y) ^ (x & z) ^ (y & z);

}

/*
 * Pad the input array to an even multiple of 512 bits.
 */
ByteArray SHA256:: pad(const ByteArray& in) {

    // Message size in bits - l
    long l = in.getLength() * 8;

    /*
     * Pad the message such that k + 1 + l is congruent to
     * 448 mod 512, where k + 1 is the padding length and l is the
     * message length. The message is always padded with a byte
     * value of 0x80, which is a single bit added to the end of
     * the message.
     */
    ByteArray work = in;
    work.append(0x80);
    // 512 bits = 64 bytes. The padded message includes the 64 bit
    // big endian representation of the message length in bits, so
    // in order to make the message modulo 512, we add bytes until
    // the whole message, including the length encoding is an even
    // multiple of 64,
    while ((work.getLength() + 8)  % 64 != 0) {
        work.append(0); //pad with zeroes.
    }
    // Append the 64 bit encoded bit length
    Scalar64 l64(l);
    work.append(l64.getEncoded(Scalar64::BIGENDIAN));
    return work;

}

/*
 * Logical rotate right function.
 */
unsigned SHA256::ror(unsigned reg, int count) {

    unsigned msb = (UINT_MAX >> 1) ^ UINT_MAX;
    unsigned result = reg;
    for (int i = 1; i <= count; ++i) {
        unsigned carry = result & 1;
        result = (result >> 1) | (carry * msb);
    }
    return result;
    
}

/*
 * σ0(X) = RotR(X, 7) ⊕ RotR(X, 18) ⊕ ShR(X, 3)
 */
unsigned SHA256::sigma0(unsigned x) {

    return ror(x, 7) ^ ror(x, 18) ^ (x >> 3);

}

/*
 * σ1(X) = RotR(X, 17) ⊕ RotR(X, 19) ⊕ ShR(X, 10),
 */
unsigned SHA256::sigma1(unsigned x) {

    return ror(x, 17) ^ ror(x, 19) ^ (x >> 10);

}

/*
 * Σ0(X) = RotR(X, 2) ⊕ RotR(X, 13) ⊕ RotR(X, 22)
 */
unsigned SHA256::Sigma0(unsigned x) {

    return ror(x, 2) ^ ror(x, 13) ^ ror(x, 22);

}

/*
 * Σ1(X) = RotR(X, 6) ⊕ RotR(X, 11) ⊕ RotR(X, 25)
 */
unsigned SHA256::Sigma1(unsigned x) {

    return ror(x, 6) ^ ror(x, 11) ^ ror(x, 25);

}

}

