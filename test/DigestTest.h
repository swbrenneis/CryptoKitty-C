#ifndef DIGESTTEST_H_INCLUDED
#define DIGESTTEST_H_INCLUDED

class DigestTest {

    public:
        DigestTest();
        ~DigestTest();

    private:
        DigestTest(const DigestTest&);
        DigestTest& operator= (const DigestTest&);

    public:
        bool sha1Test();
        bool sha256Test();
        bool sha384Test();
        bool sha512Test();

};

#endif  // DIGESTTEST_H_INCLUDED
