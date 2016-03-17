#include "../include/digest/DigestBase.h"

/*
 * This class provides some common functionality.
 * It is not intended to provide a functioning digest.
 */

DigestBase::DigestBase() {
}

DigestBase::~DigestBase() {
}

/*
 * Complete a finalized digest.
 */
ByteArray DigestBase::digest() {

    ByteArray result = finalize(accumulator);
    reset();
    return result;

}

/*
 * One step hash. Accumulated updates are lost.
 */
ByteArray DigestBase::digest(const ByteArray& bytes) {

    ByteArray result = finalize(bytes);
    reset();
    return result;

}

/*
 * Clear the digest context.
 */
void DigestBase::reset() {

    accumulator.clear();

}

/*
 * Update the digest context with a byte array.
 */
void DigestBase::update(const ByteArray& bytes) {

    accumulator.append(bytes);

}

/*
 * Update the digest context with a byte.
 */
void DigestBase::update(unsigned char byte) {

    accumulator.append(byte);

}

/*
 * Update the digest with a subrange of a message.
 */
void DigestBase::update(const ByteArray& bytes, unsigned offset, unsigned length) {

    accumulator.append(bytes.range(offset, length));

}

