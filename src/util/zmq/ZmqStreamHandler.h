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

#ifndef ZMQSTREAMHANDLER_CLASS
#define ZMQSTREAMHANDLER_CLASS

#include <string>
#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <unordered_map>
#include <memory>
#include <functional>

#include "../../nativestore/DataPublisher.h"
#include "../../partitioner/stream/Partitioner.h"
#include "../logger/Logger.h"
#include "ZmqCC.h"
#include "../../metadb/SQLiteDBInterface.h"
#include "../../temporalstore/TemporalStore.h"

class ZmqStreamHandler {
 public:
    ZmqStreamHandler(ZmqConnector *zmqConn, int numberOfPartitions,
                     std::vector<DataPublisher *> &workerClients, SQLiteDBInterface* sqlite,
                     int graphId, bool isDirected, spt::Algorithms algo = spt::Algorithms::HASH);
    ~ZmqStreamHandler();
    void listen_to_zmq_endpoint();
    Partitioner graphPartitioner;
    int graphId;
    uint32_t currentSnapshot;

    // Temporal storage: one store per partition + central store for cross-partition edges
    std::map<int, TemporalStore*> localTemporalStores;
    TemporalStore* centralTemporalStore;
    uint32_t globalSnapshotId;

 private:
    ZmqConnector *zmqConn;
    Logger zmq_logger;
    std::vector<DataPublisher *> &workerClients;
    int numberOfPartitions;

    // Batch publishing optimization
    static constexpr size_t BATCH_SIZE = 1000;
    std::vector<std::vector<std::string>> workerBatches;
    std::vector<std::unique_ptr<std::mutex>> workerBatchMutexes;
    void flushWorkerBatch(int workerId, bool force = false);

    // Async publishing with thread pool
    static constexpr int PUBLISH_THREADS = 4;
    std::vector<std::thread> publishThreads;
    std::queue<std::function<void()>> publishQueue;
    std::mutex queueMutex;
    std::condition_variable queueCV;
    std::atomic<bool> stopPublishing;
    std::atomic<bool> snapshotsFinalized;
    void startPublishThreads();
    void stopPublishThreads();
    void publishWorker();
    void enqueuePublish(std::function<void()> task);
    void finalizeAllSnapshots();
    void createGlobalSnapshot();

    // Partition caching optimization
    std::unordered_map<std::string, long> partitionCache;
    std::mutex cacheMutex;
    long getCachedPartition(const std::string& nodeId, bool* cacheHit);
    void cachePartition(const std::string& nodeId, long partition);
};

#endif
