#ifndef ZMQCONNECTOR_CLASS
#define ZMQCONNECTOR_CLASS

#include <zmq.hpp>

#include <string>
#include <vector>

class ZmqConnector {
 public:
    ZmqConnector(const std::string& endpoint);
    ~ZmqConnector();

    /**
     * Blocking receive of a single message.
     * @return The message content as a string, or empty string on error.
     */
    std::string receive();

    /**
     * Poll and receive up to maxMessages messages within timeoutMs.
     * @param maxMessages Maximum number of messages to receive in this batch.
     * @param timeoutMs Timeout in milliseconds for polling.
     * @return A vector of message strings received.
     */
    std::vector<std::string> receiveBatch(size_t maxMessages, int timeoutMs = 1000);

    /**
     * Disconnect and close the socket.
     */
    void disconnect();

 private:
    zmq::context_t context;
    zmq::socket_t socket;
    std::string endpoint;
    bool connected;
};

#endif
