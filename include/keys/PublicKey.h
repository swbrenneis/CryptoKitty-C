#ifndef PUBLICKEY_H_INCLUDED
#define PUBLICKEY_H_INCLUDED

#include <string>

namespace CK {

class PublicKey {

    private:
        PublicKey();    // Must always be constructed
                        // with an algorithm name.

    protected:
        PublicKey(const std::string& alg);

    private:
        PublicKey(const PublicKey& other);
        PublicKey& operator= (const PublicKey& other);

    public:
        virtual ~PublicKey();

    public:
        virtual const std::string& getAlgorithm() const;

    private:
        std::string algorithm;

};

}

#endif  // PUBLICKEY_H_INCLUDED
