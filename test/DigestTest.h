#include "../include/digest/CKSHA256.h"

class DigestTest {

    public:
        DigestTest();
        ~DigestTest();

    private:
        DigestTest(const DigestTest&);
        DigestTest& operator= (const DigestTest&);

    public:
        bool sha256Test();

    private:
        CKSHA256 sha256;

};
