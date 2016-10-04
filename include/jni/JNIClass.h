#ifndef JNICLASS_H_INCLUDED
#define JNICLASS_H_INCLUDED

namespace CK {

/**
 * This is an empty superclass to enable the dispose method for
 * JNI backing classes. See JNIReference.java in the CryptoKitty Java
 * tree.
 */
class JNIClass {

    public:
        JNIClass() {}
        virtual ~JNIClass() {}

    private:
        JNIClass(const JNIClass& other);
        JNIClass& operator= (const JNIClass& other);

};

}

#endif // JNICLASS_H_INCLUDED

