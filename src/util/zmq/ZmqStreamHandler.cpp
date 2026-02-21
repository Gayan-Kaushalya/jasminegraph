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

#include "ZmqStreamHandler.h"

#include <chrono>
#include <nlohmann/json.hpp>
#include <string>
#include <stdlib.h>
#include <sys/stat.h>

#include "../logger/Logger.h"
#include "../Utils.h"
#include "../../server/JasmineGraphServer.h"
#include "../../temporalstore/TemporalStorePersistence.h"
#include "../telemetry/OpenTelemetryUtil.h"

using json = nlohmann::json;
using namespace std;
using namespace std::chrono;
Logger zmq_stream_handler_logger;

ZmqStreamHandler::ZmqStreamHandler(ZmqConnector *zmqConn, int numberOfPartitions,
                                   vector<DataPublisher *> &workerClients, SQLiteDBInterface* sqlite,
                                   int graphId, bool isDirected, spt::Algorithms algorithms)
        : zmqConn(zmqConn),
          graphId(graphId),
          workerClients(workerClients),
          graphPartitioner(numberOfPartitions, graphId, algorithms, sqlite, isDirected),
          currentSnapshot(0),
          centralTemporalStore(nullptr),
          numberOfPartitions(numberOfPartitions),
          stopPublishing(false),
          snapshotsFinalized(false),
          globalSnapshotId(0) {

    // Initialize batch buffers for each worker
    workerBatches.resize(workerClients.size());
    for (size_t i = 0; i < workerClients.size(); i++) {
        workerBatchMutexes.push_back(std::make_unique<std::mutex>());
    }

    // Start async publish thread pool
    startPublishThreads();

    zmq_stream_handler_logger.info("Initialized ZmqStreamHandler with " + std::to_string(workerClients.size()) +
                              " workers, batch size " + std::to_string(BATCH_SIZE) +
                              ", " + std::to_string(PUBLISH_THREADS) + " publish threads");

    std::string temporalEnabled = Utils::getJasmineGraphProperty("org.jasminegraph.temporal.enabled");
    if (temporalEnabled == "true") {
        uint64_t timeThreshold = 60;
        uint64_t edgeThreshold = 10000;

        std::string timeStr = Utils::getJasmineGraphProperty("org.jasminegraph.temporal.snapshot.time.seconds");
        if (!timeStr.empty()) {
            timeThreshold = std::stoull(timeStr);
        }

        std::string edgeStr = Utils::getJasmineGraphProperty("org.jasminegraph.temporal.snapshot.edge.count");
        if (!edgeStr.empty()) {
            edgeThreshold = std::stoull(edgeStr);
        }

        for (int partitionId = 0; partitionId < numberOfPartitions; partitionId++) {
            localTemporalStores[partitionId] = new TemporalStore(
                graphId, partitionId, timeThreshold, edgeThreshold,
                SnapshotManager::SnapshotMode::HYBRID
            );
        }

        centralTemporalStore = new TemporalStore(
            graphId, numberOfPartitions, timeThreshold, edgeThreshold,
            SnapshotManager::SnapshotMode::HYBRID
        );

        // Restore snapshot state from disk if snapshots exist
        std::string snapshotDir = Utils::getJasmineGraphHome() + "/env/data/temporal_snapshots";

        struct stat st;
        if (stat(snapshotDir.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
            uint32_t maxGlobalSnapshotId = 0;
            bool foundAnySnapshot = false;

            for (int partitionId = 0; partitionId < numberOfPartitions; partitionId++) {
                uint32_t maxSnapshotId = TemporalStorePersistence::findHighestSnapshotId(
                    snapshotDir, graphId, partitionId);

                if (maxSnapshotId != UINT32_MAX) {
                    foundAnySnapshot = true;
                    if (maxSnapshotId > maxGlobalSnapshotId) {
                        maxGlobalSnapshotId = maxSnapshotId;
                    }

                    std::string snapshotFilePath = TemporalStorePersistence::generateFilePath(
                        snapshotDir, graphId, partitionId, maxSnapshotId);

                    if (localTemporalStores[partitionId]->loadSnapshotFromDisk(snapshotFilePath)) {
                        localTemporalStores[partitionId]->getSnapshotManager()->setCurrentSnapshotId(maxSnapshotId);
                        uint32_t newSnapshotId = localTemporalStores[partitionId]->openNewSnapshot();

                        zmq_stream_handler_logger.info("Restored temporal state for graph " + std::to_string(graphId) +
                                                  " partition " + std::to_string(partitionId) +
                                                  " from snapshot " + std::to_string(maxSnapshotId) +
                                                  ", continuing with snapshot " + std::to_string(newSnapshotId));
                    } else {
                        zmq_stream_handler_logger.error("Failed to load snapshot for graph " + std::to_string(graphId) +
                                                   " partition " + std::to_string(partitionId) +
                                                   " from snapshot " + std::to_string(maxSnapshotId));
                    }
                }
            }

            // Restore central store
            uint32_t maxCentralSnapshotId = TemporalStorePersistence::findHighestSnapshotId(
                snapshotDir, graphId, numberOfPartitions);

            if (maxCentralSnapshotId != UINT32_MAX) {
                foundAnySnapshot = true;
                if (maxCentralSnapshotId > maxGlobalSnapshotId) {
                    maxGlobalSnapshotId = maxCentralSnapshotId;
                }

                std::string centralSnapshotFilePath = TemporalStorePersistence::generateFilePath(
                    snapshotDir, graphId, numberOfPartitions, maxCentralSnapshotId);

                if (centralTemporalStore->loadSnapshotFromDisk(centralSnapshotFilePath)) {
                    centralTemporalStore->getSnapshotManager()->setCurrentSnapshotId(maxCentralSnapshotId);
                    uint32_t newCentralSnapshotId = centralTemporalStore->openNewSnapshot();

                    zmq_stream_handler_logger.info("Restored central temporal state for graph " + std::to_string(graphId) +
                                              " from snapshot " + std::to_string(maxCentralSnapshotId) +
                                              ", continuing with snapshot " + std::to_string(newCentralSnapshotId));
                } else {
                    zmq_stream_handler_logger.error("Failed to load central snapshot for graph " + std::to_string(graphId) +
                                               " from snapshot " + std::to_string(maxCentralSnapshotId));
                }
            }

            if (foundAnySnapshot) {
                globalSnapshotId = maxGlobalSnapshotId + 1;
                zmq_stream_handler_logger.info("Global snapshot ID restored to " + std::to_string(globalSnapshotId) +
                                          " (continuing from highest snapshot " + std::to_string(maxGlobalSnapshotId) + ")");
            }
        }

        zmq_stream_handler_logger.info("Temporal storage enabled for graph " + std::to_string(graphId) +
                                  " with " + std::to_string(numberOfPartitions) + " partitions");
    }
}

// Destructor: Clean up temporal stores to prevent memory leaks
ZmqStreamHandler::~ZmqStreamHandler() {
    stopPublishThreads();

    for (size_t i = 0; i < workerBatches.size(); i++) {
        flushWorkerBatch(i, true);
    }

    finalizeAllSnapshots();

    for (auto& [partitionId, store] : localTemporalStores) {
        if (store != nullptr) {
            delete store;
        }
    }
    localTemporalStores.clear();

    if (centralTemporalStore != nullptr) {
        delete centralTemporalStore;
        centralTemporalStore = nullptr;
    }
}

void ZmqStreamHandler::finalizeAllSnapshots() {
    bool expected = false;
    if (!snapshotsFinalized.compare_exchange_strong(expected, true)) {
        return;
    }

    if (localTemporalStores.empty() && centralTemporalStore == nullptr) {
        return;
    }

    zmq_stream_handler_logger.info("Finalizing all temporal snapshots (saving open snapshots)");

    std::string snapshotDir = Utils::getJasmineGraphHome() + "/env/data/temporal_snapshots";
    Utils::createDirectory(snapshotDir);

    for (auto& [partitionId, store] : localTemporalStores) {
        if (store != nullptr) {
            try {
                if (store->saveSnapshotToDisk(snapshotDir, false)) {
                    zmq_stream_handler_logger.info("Saved final snapshot for partition " +
                                              std::to_string(partitionId));
                } else {
                    zmq_stream_handler_logger.error("Failed to save final snapshot for partition " +
                                               std::to_string(partitionId));
                }
            } catch (const std::exception& e) {
                zmq_stream_handler_logger.error("Exception saving partition " +
                                           std::to_string(partitionId) + ": " + e.what());
            }
        }
    }

    if (centralTemporalStore != nullptr) {
        try {
            if (centralTemporalStore->saveSnapshotToDisk(snapshotDir, false)) {
                zmq_stream_handler_logger.info("Saved final central snapshot");
            } else {
                zmq_stream_handler_logger.error("Failed to save final central snapshot");
            }
        } catch (const std::exception& e) {
            zmq_stream_handler_logger.error("Exception saving central snapshot: " + std::string(e.what()));
        }
    }
}

void ZmqStreamHandler::createGlobalSnapshot() {
    std::string snapshotDir = Utils::getJasmineGraphHome() + "/env/data/temporal_snapshots";
    Utils::createDirectory(snapshotDir);

    zmq_stream_handler_logger.info("Creating GLOBAL snapshot " + std::to_string(globalSnapshotId) +
                              " for ALL partitions");

    int partitionsSaved = 0;
    for (auto& [partitionId, store] : localTemporalStores) {
        if (store != nullptr) {
            try {
                if (store->saveSnapshotToDisk(snapshotDir, false)) {
                    zmq_stream_handler_logger.info("Saved global snapshot " + std::to_string(globalSnapshotId) +
                                              " for partition " + std::to_string(partitionId));
                    partitionsSaved++;
                } else {
                    zmq_stream_handler_logger.error("Failed to save global snapshot " +
                                               std::to_string(globalSnapshotId) +
                                               " for partition " + std::to_string(partitionId));
                }
            } catch (const std::exception& e) {
                zmq_stream_handler_logger.error("Exception saving partition " + std::to_string(partitionId) +
                                           " snapshot " + std::to_string(globalSnapshotId) + ": " + e.what());
            }
        }
    }

    if (centralTemporalStore != nullptr) {
        try {
            if (centralTemporalStore->saveSnapshotToDisk(snapshotDir, false)) {
                zmq_stream_handler_logger.info("Saved global snapshot " + std::to_string(globalSnapshotId) +
                                          " for central store");
            } else {
                zmq_stream_handler_logger.error("Failed to save central store global snapshot " +
                                           std::to_string(globalSnapshotId));
            }
        } catch (const std::exception& e) {
            zmq_stream_handler_logger.error("Exception saving central store snapshot " +
                                       std::to_string(globalSnapshotId) + ": " + e.what());
        }
    }

    for (auto& [partitionId, store] : localTemporalStores) {
        if (store != nullptr) {
            store->openNewSnapshot();
        }
    }
    if (centralTemporalStore != nullptr) {
        centralTemporalStore->openNewSnapshot();
    }

    globalSnapshotId++;

    zmq_stream_handler_logger.info("Global snapshot created across " + std::to_string(partitionsSaved) +
                              " partitions. Next snapshot ID: " + std::to_string(globalSnapshotId));
}

// ============================================================================
// OPTIMIZATION METHODS: Batch Publishing + Async Thread Pool + Partition Cache
// ============================================================================

void ZmqStreamHandler::startPublishThreads() {
    for (int i = 0; i < PUBLISH_THREADS; i++) {
        publishThreads.emplace_back(&ZmqStreamHandler::publishWorker, this);
    }
}

void ZmqStreamHandler::stopPublishThreads() {
    stopPublishing = true;
    queueCV.notify_all();
    for (auto& thread : publishThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

void ZmqStreamHandler::publishWorker() {
    while (!stopPublishing) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCV.wait(lock, [this]{ return !publishQueue.empty() || stopPublishing; });
            if (stopPublishing && publishQueue.empty()) return;
            if (!publishQueue.empty()) {
                task = std::move(publishQueue.front());
                publishQueue.pop();
            }
        }
        if (task) {
            task();
        }
    }
}

void ZmqStreamHandler::enqueuePublish(std::function<void()> task) {
    std::unique_lock<std::mutex> lock(queueMutex);
    publishQueue.push(std::move(task));
    queueCV.notify_one();
}

void ZmqStreamHandler::flushWorkerBatch(int workerId, bool force) {
    std::unique_lock<std::mutex> lock(*workerBatchMutexes[workerId]);

    if (workerBatches[workerId].empty()) return;
    if (!force && workerBatches[workerId].size() < BATCH_SIZE) return;

    std::vector<std::string> edges = std::move(workerBatches[workerId]);
    workerBatches[workerId].clear();
    lock.unlock();

    for (const auto& edgeData : edges) {
        enqueuePublish([this, workerId, edgeData]() {
            try {
                workerClients[workerId]->publish(edgeData);
            } catch (const std::exception& e) {
                zmq_stream_handler_logger.error("Failed to publish edge to worker " +
                                           std::to_string(workerId) + ": " + e.what());
            }
        });
    }
}

long ZmqStreamHandler::getCachedPartition(const std::string& nodeId, bool* cacheHit) {
    std::lock_guard<std::mutex> lock(cacheMutex);
    auto it = partitionCache.find(nodeId);
    if (it != partitionCache.end()) {
        *cacheHit = true;
        return it->second;
    }
    *cacheHit = false;
    return -1;
}

void ZmqStreamHandler::cachePartition(const std::string& nodeId, long partition) {
    std::lock_guard<std::mutex> lock(cacheMutex);
    if (partitionCache.size() < 100000) {
        partitionCache[nodeId] = partition;
    }
}

void ZmqStreamHandler::listen_to_zmq_endpoint() {
    // Start automatic OpenTelemetry tracing for entire streaming session
    OTEL_TRACE_FUNCTION();

    OpenTelemetryUtil::addSpanAttribute("graph.id", std::to_string(graphId));
    OpenTelemetryUtil::addSpanAttribute("partitions", std::to_string(numberOfPartitions));
    OpenTelemetryUtil::addSpanAttribute("temporal.enabled", !localTemporalStores.empty() ? "true" : "false");
    OpenTelemetryUtil::addSpanAttribute("transport", "zeromq");

    // Get workers
    JasmineGraphServer *server = JasmineGraphServer::getInstance();
    std::vector<JasmineGraphServer::worker> workers = server->workers(workerClients.size());

    // Assign partitions to workers
    for (int i = 0; i < workerClients.size(); i++) {
        Utils::assignPartitionToWorker(graphId, i, workers.at(i).hostname, workers.at(i).port);
    }

    uint64_t messagesProcessed = 0;
    uint64_t emptyPolls = 0;
    uint64_t localEdgesAdded = 0;
    uint64_t centralEdgesAdded = 0;
    const uint64_t MAX_CONSECUTIVE_EMPTY_POLLS = 60;

    auto total_parse_time = std::chrono::microseconds(0);
    auto total_partition_time = std::chrono::microseconds(0);
    auto total_temporal_time = std::chrono::microseconds(0);
    auto total_publish_time = std::chrono::microseconds(0);

    zmq_stream_handler_logger.info("Starting ZeroMQ consumer loop for graph " + std::to_string(graphId));

    const size_t ZMQ_BATCH_SIZE = 2000;
    bool receivedTermination = false;

    while (!receivedTermination) {
        // Poll batch of messages from ZMQ PULL socket
        std::vector<std::string> messageBatch = zmqConn->receiveBatch(ZMQ_BATCH_SIZE, 1000);

        if (messageBatch.empty()) {
            emptyPolls++;

            if (messagesProcessed > 0 && emptyPolls >= MAX_CONSECUTIVE_EMPTY_POLLS) {
                zmq_stream_handler_logger.info("Stream timeout: No messages for " +
                                          std::to_string(MAX_CONSECUTIVE_EMPTY_POLLS) + " seconds");
                zmq_stream_handler_logger.info("Edges added: " + std::to_string(localEdgesAdded) + " local, " +
                                          std::to_string(centralEdgesAdded) + " central");
                zmq_stream_handler_logger.warn("Did not receive termination signal (-1). Exiting due to timeout.");
                break;
            }
            continue;
        }

        emptyPolls = 0;

        for (auto& data : messageBatch) {
            // Check for termination signal
            if (data == "-1") {
                zmq_stream_handler_logger.info("Received termination signal (-1) from ZeroMQ");
                zmq_stream_handler_logger.info("Total messages processed: " + std::to_string(messagesProcessed));
                zmq_stream_handler_logger.info("Edges added: " + std::to_string(localEdgesAdded) + " local, " +
                                          std::to_string(centralEdgesAdded) + " central");

                // Flush all batches before sending termination signal
                zmq_stream_handler_logger.info("Flushing all batches before termination...");
                for (size_t i = 0; i < workerBatches.size(); i++) {
                    flushWorkerBatch(i, true);
                }

                // Wait for async publish queue to drain
                int waitCount = 0;
                while (waitCount < 50) {
                    std::unique_lock<std::mutex> lock(queueMutex);
                    if (publishQueue.empty()) break;
                    lock.unlock();
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    waitCount++;
                }

                // Send termination signal to all workers
                for (auto &workerClient : workerClients) {
                    if (workerClient != nullptr) {
                        workerClient->publish("-1");
                    }
                }
                receivedTermination = true;
                break;
            }

            // Skip empty messages
            if (data.empty()) {
                continue;
            }

            messagesProcessed++;

            // Reduce tracing overhead: only trace every 1000th message
            bool shouldTrace = (messagesProcessed % 1000 == 0);
            ScopedTracer* message_tracer = nullptr;
            if (shouldTrace) {
                message_tracer = new ScopedTracer("process_zmq_batch", {
                    {"batch.size", std::to_string(messageBatch.size())},
                    {"messages.processed", std::to_string(messagesProcessed)},
                    {"graph.id", std::to_string(graphId)}
                });
            }

            // 1. JSON PARSING
            auto parse_start = std::chrono::high_resolution_clock::now();
            json edgeJson;
            try {
                edgeJson = json::parse(data);
            } catch (const json::parse_error& e) {
                zmq_stream_handler_logger.error("JSON parse error: " + std::string(e.what()) +
                                           " for data: " + data.substr(0, 100));
                if (message_tracer) delete message_tracer;
                continue;
            }

            auto prop = edgeJson["properties"];
            prop["graphId"] = to_string(this->graphId);
            auto sourceJson = edgeJson["source"];
            auto destinationJson = edgeJson["destination"];
            string sId = std::string(sourceJson["id"]);
            string dId = std::string(destinationJson["id"]);
            auto parse_duration = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::high_resolution_clock::now() - parse_start);
            total_parse_time += parse_duration;

            // 2. PARTITIONING
            auto partition_start = std::chrono::high_resolution_clock::now();
            partitionedEdge partEdge = graphPartitioner.addEdge({sId, dId});
            long part_s = partEdge[0].second;
            long part_d = partEdge[1].second;
            auto partition_duration = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::high_resolution_clock::now() - partition_start);
            total_partition_time += partition_duration;
            sourceJson["pid"] = part_s;
            destinationJson["pid"] = part_d;
            json obj;
            obj["source"] = sourceJson;
            obj["destination"] = destinationJson;
            obj["properties"] = prop;

            int n_workers = atoi((Utils::getJasmineGraphProperty("org.jasminegraph.server.nworkers")).c_str());
            long temp_s = part_s % n_workers;
            long temp_d = part_d % n_workers;

            // 3. TEMPORAL STORE OPERATIONS
            auto temporal_start = std::chrono::high_resolution_clock::now();
            bool shouldCreateGlobalSnapshot = false;

            if (!localTemporalStores.empty()) {
                try {
                    if (part_s == part_d) {
                        if (localTemporalStores.find(part_s) == localTemporalStores.end()) {
                            zmq_stream_handler_logger.error("Invalid partition ID " + std::to_string(part_s) +
                                                       " for edge " + sId + "-" + dId);
                            if (message_tracer) delete message_tracer;
                            continue;
                        }
                        localTemporalStores[part_s]->addEdge(sId, dId, globalSnapshotId);
                        localEdgesAdded++;

                        if (localTemporalStores[part_s]->shouldCreateSnapshot()) {
                            shouldCreateGlobalSnapshot = true;
                        }
                    } else {
                        if (centralTemporalStore == nullptr) {
                            zmq_stream_handler_logger.error("Central temporal store is null for edge " + sId + "-" + dId);
                            if (message_tracer) delete message_tracer;
                            continue;
                        }
                        centralTemporalStore->addEdge(sId, dId, globalSnapshotId);
                        centralEdgesAdded++;

                        if (centralTemporalStore->shouldCreateSnapshot()) {
                            shouldCreateGlobalSnapshot = true;
                        }
                    }

                    if (shouldCreateGlobalSnapshot) {
                        OTEL_TRACE_OPERATION("save_global_snapshot");
                        OpenTelemetryUtil::addSpanAttribute("snapshot.id", std::to_string(globalSnapshotId));
                        OpenTelemetryUtil::addSpanAttribute("trigger.partition", std::to_string(part_s));

                        createGlobalSnapshot();
                    }
                } catch (const std::bad_alloc& e) {
                    zmq_stream_handler_logger.error("CRITICAL: Memory allocation failed at edge " +
                                               std::to_string(messagesProcessed) +
                                               ". Attempting emergency snapshot save...");

                    if (message_tracer) {
                        message_tracer->setStatus(trace_api::StatusCode::kError, "Memory allocation failed");
                        delete message_tracer;
                    }

                    std::string snapshotDir = Utils::getJasmineGraphHome() + "/env/data/temporal_snapshots";
                    Utils::createDirectory(snapshotDir);

                    bool savedAny = false;
                    for (auto& [partitionId, store] : localTemporalStores) {
                        if (store != nullptr && store->saveSnapshotToDisk(snapshotDir, false)) {
                            zmq_stream_handler_logger.info("Emergency saved partition " + std::to_string(partitionId));
                            savedAny = true;
                        }
                    }
                    if (centralTemporalStore != nullptr && centralTemporalStore->saveSnapshotToDisk(snapshotDir, false)) {
                        zmq_stream_handler_logger.info("Emergency saved central store");
                        savedAny = true;
                    }

                    if (savedAny) {
                        zmq_stream_handler_logger.error("Emergency snapshots saved. Terminating stream processing.");
                    } else {
                        zmq_stream_handler_logger.error("Failed to save emergency snapshots. Data may be lost.");
                    }

                    throw;
                } catch (const std::exception& e) {
                    zmq_stream_handler_logger.error("Exception while adding edge " + sId + "-" + dId + ": " + e.what());
                    if (message_tracer) {
                        message_tracer->setStatus(trace_api::StatusCode::kError, e.what());
                    }
                }
            }
            auto temporal_duration = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::high_resolution_clock::now() - temporal_start);
            total_temporal_time += temporal_duration;

            // 4. WORKER Publishing - batch publishing
            auto publish_start = std::chrono::high_resolution_clock::now();

            std::string edgeData = obj.dump();
            if (part_s == part_d) {
                obj["EdgeType"] = "Local";
                obj["PID"] = part_s;
                std::string localEdgeData = obj.dump();

                std::unique_lock<std::mutex> lock(*workerBatchMutexes[temp_s]);
                workerBatches[temp_s].push_back(localEdgeData);
                size_t batchSize = workerBatches[temp_s].size();
                lock.unlock();

                if (batchSize >= BATCH_SIZE) {
                    flushWorkerBatch(temp_s, false);
                }
            } else {
                obj["EdgeType"] = "Central";
                obj["PID"] = part_s;
                std::string centralEdgeData_s = obj.dump();

                obj["PID"] = part_d;
                std::string centralEdgeData_d = obj.dump();

                {
                    std::unique_lock<std::mutex> lock(*workerBatchMutexes[temp_s]);
                    workerBatches[temp_s].push_back(centralEdgeData_s);
                    size_t batchSize = workerBatches[temp_s].size();
                    lock.unlock();
                    if (batchSize >= BATCH_SIZE) {
                        flushWorkerBatch(temp_s, false);
                    }
                }
                {
                    std::unique_lock<std::mutex> lock(*workerBatchMutexes[temp_d]);
                    workerBatches[temp_d].push_back(centralEdgeData_d);
                    size_t batchSize = workerBatches[temp_d].size();
                    lock.unlock();
                    if (batchSize >= BATCH_SIZE) {
                        flushWorkerBatch(temp_d, false);
                    }
                }
            }

            auto publish_duration = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::high_resolution_clock::now() - publish_start);
            total_publish_time += publish_duration;
            if (message_tracer) {
                delete message_tracer;
            }
        }  // End of message batch processing

        // Periodically flush all batches
        if (messagesProcessed % 1000 == 0) {
            for (size_t i = 0; i < workerBatches.size(); i++) {
                flushWorkerBatch(i, false);
            }
        }

        // Log performance statistics every 10000 messages
        if (messagesProcessed > 0 && messagesProcessed % 10000 == 0) {
            OTEL_TRACE_OPERATION("zmq_streaming_performance_checkpoint");

            auto avg_parse = total_parse_time.count() / messagesProcessed;
            auto avg_partition = total_partition_time.count() / messagesProcessed;
            auto avg_temporal = total_temporal_time.count() / messagesProcessed;
            auto avg_publish = total_publish_time.count() / messagesProcessed;
            auto avg_total = avg_parse + avg_partition + avg_temporal + avg_publish;

            OpenTelemetryUtil::addSpanAttribute("messages.processed", std::to_string(messagesProcessed));
            OpenTelemetryUtil::addSpanAttribute("avg.parse_us", std::to_string(avg_parse));
            OpenTelemetryUtil::addSpanAttribute("avg.partition_us", std::to_string(avg_partition));
            OpenTelemetryUtil::addSpanAttribute("avg.temporal_us", std::to_string(avg_temporal));
            OpenTelemetryUtil::addSpanAttribute("avg.publish_us", std::to_string(avg_publish));
            OpenTelemetryUtil::addSpanAttribute("avg.total_us", std::to_string(avg_total));

            if (avg_total > 0) {
                OpenTelemetryUtil::addSpanAttribute("pct.parse", std::to_string(100 * avg_parse / avg_total));
                OpenTelemetryUtil::addSpanAttribute("pct.partition", std::to_string(100 * avg_partition / avg_total));
                OpenTelemetryUtil::addSpanAttribute("pct.temporal", std::to_string(100 * avg_temporal / avg_total));
                OpenTelemetryUtil::addSpanAttribute("pct.publish", std::to_string(100 * avg_publish / avg_total));
            }

            zmq_stream_handler_logger.info("ZMQ Performance @ " + std::to_string(messagesProcessed) + " messages: " +
                "parse=" + std::to_string(avg_parse) + "us, " +
                "partition=" + std::to_string(avg_partition) + "us, " +
                "temporal=" + std::to_string(avg_temporal) + "us, " +
                "publish=" + std::to_string(avg_publish) + "us");
        }
    }  // End of main loop

    // Final flush
    zmq_stream_handler_logger.info("ZMQ stream ended. Flushing remaining batches...");
    for (size_t i = 0; i < workerBatches.size(); i++) {
        flushWorkerBatch(i, true);
    }

    // Save final snapshots
    finalizeAllSnapshots();

    zmq_stream_handler_logger.info("ZMQ stream handler completed for graph " + std::to_string(graphId) +
                              ". Total edges: " + std::to_string(localEdgesAdded) + " local, " +
                              std::to_string(centralEdgesAdded) + " central");
}
