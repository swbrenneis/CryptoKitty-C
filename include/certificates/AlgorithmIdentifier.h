#ifndef ALGORITHMIDENTIFIER_H_INCLUDED
#define ALGORITHMIDENTIFIER_H_INCLUDED

#include "certificates/Encodable.h"

namespace CK {

class ObjectID;

class AlgorithmIdentifier : public Encodable {

    protected:
        AlgorithmIdentifier();

    public:
        virtual ~AlgorithmIdentifier();

    private:
        AlgorithmIdentifier(const AlgorithmIdentifier& other);
        AlgorithmIdentifier& operator= (const AlgorithmIdentifier& other);

    public:
        ByteArray encode() const;
        ObjectID *getAlgorithm();
        Encodable *getParameters();
        void setAlgorithm(ObjectID *alg);
        void setParameters(Encodable *params);

    private:
        ObjectID *algorithm;
        Encodable *parameters;

};

}

#endif  // ALGORITHMIDENTIFIER_H_INCLUDED
