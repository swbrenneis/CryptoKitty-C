#include "certificates/AlgorithmIdentifier.h"
#include "certificates/ObjectID.h"

namespace CK {

AlgorithmIdentifier::AlgorithmIdentifier() {
}

AlgorithmIdentifier::~AlgorithmIdentifier() {
}

ByteArray AlgorithmIdentifier::encode() const {

    ByteArray result;
    result.append(UNIVERSAL | CONSTRUCTED | SEQUENCE);

    ByteArray alg(algorithm->encode());
    ByteArray param(parameters->encode());
    result.append(encodeLength(alg.getLength() + param.getLength()));
    result.append(alg);
    result.append(param);

    return result;

}

ObjectID *AlgorithmIdentifier::getAlgorithm() {

    return algorithm;

}

Encodable *AlgorithmIdentifier::getParameters() {

    return parameters;

}

void AlgorithmIdentifier::setAlgorithm(ObjectID *alg) {

    algorithm = alg;

}

void AlgorithmIdentifier::setParameters(Encodable *params) {

    parameters = params;

}

}
