#ifndef SIGNATURETEST_H_INCLUDED
#define SIGNATURETEST_H_INCLUDED

class SignatureTest {

    public:
        SignatureTest();
        ~SignatureTest();

    private:
        SignatureTest(const SignatureTest& other);
        SignatureTest& operator= (const SignatureTest& other);

    public:
        bool RSAPKCS1test(int keysize);
        bool RSAPSStest(int keysize);

};

#endif  // SIGNATURETEST_H_INCLUDED
