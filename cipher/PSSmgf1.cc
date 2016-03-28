#include "cipher/PSSmgf1.h"
#include "digest/Digest.h"
#include "data/Scalar32.h"
#include "exceptions/BadParameterException.h"
#include <cmath>

namespace CK {
        
PSSmgf1::PSSmgf1(Digest *digest)
: hash(digest) {
}

PSSmgf1::~PSSmgf1() {
}

/*
* Generate the mask.
*/
ByteArray PSSmgf1::generateMask(const ByteArray& mgfSeed, int maskLen) {

    hash->reset();
    int hLen = hash->getDigestLength();
    if (maskLen > 0x100000000L * hLen) {
        throw new BadParameterException("Mask length out of bounds");
    }

    ByteArray T;
    double doubleMaskLen = maskLen;
    for (int counter = 0; counter < std::ceil(doubleMaskLen / hLen);
                                                            ++counter) {
        ByteArray C(Scalar32(counter).getEncoded(Scalar32::BIGENDIAN));
        ByteArray h;
        h.append(mgfSeed);
        h.append(C);
        ByteArray t(hash->digest(h));

        T.append(t);
    }

    return T.range(0, maskLen);

}

}

