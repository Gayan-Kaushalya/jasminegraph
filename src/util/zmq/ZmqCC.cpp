/**
Copyright 2025 JasminGraph Team
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
**/

#include "ZmqCC.h"

#include <iostream>

ZmqConnector::ZmqConnector(const std::string& endpoint)
    : context(1), socket(context, zmq::socket_type::pull), endpoint(endpoint), connected(false) {
    // Set receive timeout to avoid indefinite blocking
    int recvTimeout = 1000;  // 1 second
    socket.set(zmq::sockopt::rcvtimeo, recvTimeout);

    // Set linger to 0 so socket closes immediately on disconnect
    int linger = 0;
    socket.set(zmq::sockopt::linger, linger);

    socket.connect(endpoint);
    connected = true;
}

ZmqConnector::~ZmqConnector() {
    disconnect();
}

std::string ZmqConnector::receive() {
    if (!connected) {
        return "";
    }

    zmq::message_t message;
    auto result = socket.recv(message, zmq::recv_flags::none);
    if (result.has_value()) {
        return std::string(static_cast<char*>(message.data()), message.size());
    }
    return "";  // Timeout or error
}

std::vector<std::string> ZmqConnector::receiveBatch(size_t maxMessages, int timeoutMs) {
    std::vector<std::string> messages;
    if (!connected) {
        return messages;
    }

    // Use zmq_poll to check for available messages
    zmq::pollitem_t items[] = {{socket, 0, ZMQ_POLLIN, 0}};

    for (size_t i = 0; i < maxMessages; i++) {
        // Poll with timeout only for the first message; subsequent messages use 0 timeout
        int pollTimeout = (i == 0) ? timeoutMs : 0;
        zmq::poll(items, 1, std::chrono::milliseconds(pollTimeout));

        if (items[0].revents & ZMQ_POLLIN) {
            zmq::message_t message;
            auto result = socket.recv(message, zmq::recv_flags::dontwait);
            if (result.has_value()) {
                messages.push_back(std::string(static_cast<char*>(message.data()), message.size()));
            } else {
                break;  // No more messages available
            }
        } else {
            break;  // No messages available
        }
    }

    return messages;
}

void ZmqConnector::disconnect() {
    if (connected) {
        try {
            socket.disconnect(endpoint);
        } catch (...) {
            // Ignore disconnect errors during cleanup
        }
        connected = false;
    }
}
