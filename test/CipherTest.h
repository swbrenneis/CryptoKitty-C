#ifndef CIPHERTEST_H_INCLUDED
#define CIPHERTEST_H_INCLUDED

class CipherTest {

    public:
        CipherTest();
        ~CipherTest();

    private:
        CipherTest(const CipherTest&);
        CipherTest& operator= (const CipherTest&);

    public:
        bool AESTest();

};

#endif  // CIPHERTEST_H_INCLUDED
