#ifndef AES_H_INCLUDED
#define AES_H_INCLUDED

#include "data/ByteArray.h"
#include <cstdint>

namespace CK {

class ByteArray;

class AES {

   public:
       enum KeySize { AES128=16, AES192=24, AES256=32 };

    public:
        AES(KeySize ks);
        ~AES();

    private:
        AES(const AES& other);
        AES& operator= (const AES& other);

    public:
        ByteArray decrypt(const ByteArray& ciphertext, const ByteArray& key);
        ByteArray encrypt(const ByteArray& plaintext, const ByteArray& key);

    private:
        typedef uint8_t Word[4];
        inline void copy(Word& a, const Word& b) const {
            a[0] = b[0]; a[1] = b[1]; a[2] = b[2]; a[3] = b[3];
        }
        void rol(int count, Word& a) const {
            uint8_t tmp;
            for (int n = 0; n < count; ++n) {
                tmp = a[3];
                a[3] = a[2];
                a[2] = a[1];
                a[1] = a[0];
                a[0] = tmp;
            }
        }
        void ror(int count, Word& a) const {
            uint8_t tmp;
            for (int n = 0; n < count; ++n) {
                tmp = a[0];
                a[0] = a[1];
                a[1] = a[2];
                a[2] = a[3];
                a[3] = tmp;
            }
        }
        struct StateArray {
            Word row0;
            Word row1;
            Word row2;
            Word row3;
        };

    private:
        void AddRoundKey(const Word *roundKey);
        void Cipher(const ByteArray& plaintext, const Word *keySchedule);
        void InvCipher(const ByteArray& ciphertext, const Word *KeySchedule);
        void InvMixColumns();
        void InvShiftRows();
        void InvSubBytes();
        void KeyExpansion(const ByteArray& key, Word *keySchedule) const;
        void MixColumns();
        uint8_t RijndaelMult(uint8_t lhs, uint8_t rhs) const;
        void Rotate(ByteArray& w) const;
        void ShiftRows();
        void SubBytes();

    private:
        KeySize keySize;
        unsigned keyScheduleSize;
        int Nk;
        int Nr;
        StateArray state;
    
        static const uint8_t Rcon[256];
        static const uint8_t Sbox[256];
        static const uint8_t InvSbox[256];
        static const int Nb;
        static const StateArray cx;
        static const StateArray invax;


};

}

#endif  // AES_H_INCLUDED
