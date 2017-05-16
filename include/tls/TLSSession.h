#ifndef TLSSESSION_H_INCLUDED
#define TLSSESSION_H_INCLUDED

#include "../jni/JNIReference.h"
#include <string>

namespace coder {
    class ByteArray;
}

namespace CK {

struct GNUTLSSession;
class TLSCredentials;

class TLSSession : public JNIReference {

    protected:
        TLSSession();

    public:
        ~TLSSession();

    private:
        TLSSession(const TLSSession& other);
        TLSSession& operator= (const TLSSession& other);

    public:
        bool doHandshake();
        const std::string& getCertError() const { return certError; }
        const std::string& getHostname() const { return hostname; }
        const std::string& getLastError() const { return lastError; }
        static TLSSession *initializeClient();
        static TLSSession *initializeServer();
        unsigned receiveRecord(coder::ByteArray& record, unsigned length);
        void sendRecord(const coder::ByteArray& record);
        void setCertError(const std::string& error) { certError = error; }
        void setCredentials(TLSCredentials *credentials);
        void setError(const std::string& error) { lastError = error; }
        void setHostname(const std::string host) { hostname = host; }
        void setRequireClientAuth(bool require);
        bool startSocketTransport(int socket);
        void tlsBye();

    private:
        std::string hostname;
        std::string certError;
        std::string lastError;
        GNUTLSSession *session;

};

}

#endif // TLSSESSION_H_INCLUDED

