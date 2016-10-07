#ifndef JNIREFERENCE_H_INCLUDED
#define JNIREFERENCE_H_INCLUDED

namespace CK {

/**
 * This is an empty superclass to enable the dispose method for
 * JNI backing classes. See JNIReference.java in the CryptoKitty Java
 * tree.
 */
class JNIReference {

    public:
        JNIReference() {}
        virtual ~JNIReference() {}

    private:
        JNIReference(const JNIReference& other);
        JNIReference& operator= (const JNIReference& other);

};

}

#endif // JNIREFERENCE_H_INCLUDED

