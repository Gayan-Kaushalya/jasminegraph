/**
Copyright 2021 JasmineGraph Team
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

#include "SheepTriangleCountExecutor.h"
#include "TriangleCountExecutor.h"

#include <netdb.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../../../../../globals.h"
#include "../../../../k8s/K8sWorkerController.h"
#include "../../../../scale/scaler.h"
#include "../../../../util/telemetry/OpenTelemetryUtil.h"

using namespace std::chrono;

Logger sheepTriangleCount_logger;

static std::mutex fileCombinationMutex;

// Use the same static variables from TriangleCountExecutor for consistency
extern std::mutex processStatusMutex;
extern std::mutex responseVectorMutex;
extern bool isStatCollect;
extern time_t last_exec_time;

SheepTriangleCountExecutor::SheepTriangleCountExecutor() {}

SheepTriangleCountExecutor::SheepTriangleCountExecutor(SQLiteDBInterface *db, PerformanceSQLiteDBInterface *perfDb,
                                                       JobRequest jobRequest) {
    this->sqlite = db;
    this->perfDB = perfDb;
    this->request = jobRequest;
}

int SheepTriangleCountExecutor::getUid() {
    static int counter = 0;
    return counter++;
}

void SheepTriangleCountExecutor::execute() {
    // Start automatic OpenTelemetry tracing for sheep triangle count execution
    std::string graphId = request.getParameter(Conts::PARAM_KEYS::GRAPH_ID);
    OTEL_TRACE_FUNCTION();

    schedulerMutex.lock();
    time_t curr_time = time(NULL);
    // 8 seconds = upper bound to the time to send performance metrics after allocating task to a worker
    if (curr_time < last_exec_time + 8) {
        sleep(last_exec_time + 9 - curr_time);  // 9 = 8+1 to ensure it waits more than 8 seconds
    }
    int uniqueId = getUid();
    std::string masterIP = request.getMasterIP();
    std::string canCalibrateString = request.getParameter(Conts::PARAM_KEYS::CAN_CALIBRATE);
    std::string queueTime = request.getParameter(Conts::PARAM_KEYS::QUEUE_TIME);

    bool canCalibrate = Utils::parseBoolean(canCalibrateString);
    int threadPriority = request.getPriority();

    std::string autoCalibrateString = request.getParameter(Conts::PARAM_KEYS::AUTO_CALIBRATION);
    bool autoCalibrate = Utils::parseBoolean(autoCalibrateString);

    if (threadPriority == Conts::HIGH_PRIORITY_DEFAULT_VALUE) {
        highPriorityGraphList.push_back(graphId);
    }

    // Below code is used to update the process details
    processStatusMutex.lock();
    std::chrono::milliseconds startTime = duration_cast<milliseconds>(system_clock::now().time_since_epoch());

    struct ProcessInfo processInformation;
    processInformation.id = uniqueId;
    processInformation.graphId = graphId;
    processInformation.processName = SHEEP_TRIANGLES;  // Use SHEEP_TRIANGLES identifier
    processInformation.priority = threadPriority;
    processInformation.startTimestamp = startTime.count();

    if (!queueTime.empty()) {
        long sleepTime = atol(queueTime.c_str());
        processInformation.sleepTime = sleepTime;
        processData.insert(processInformation);
        processStatusMutex.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
    } else {
        processData.insert(processInformation);
        processStatusMutex.unlock();
    }

    sheepTriangleCount_logger.log(
        "###SHEEP-TRIANGLE-COUNT-EXECUTOR### Started with graph ID : " + graphId + " Master IP : " + masterIP, "info");

    long result = 0;
    bool isCompositeAggregation = false;
    Utils::worker aggregatorWorker;
    std::vector<std::future<long>> intermRes;
    std::vector<std::future<int>> statResponse;
    std::vector<std::string> compositeCentralStoreFiles;

    auto begin = chrono::high_resolution_clock::now();

    string sqlStatement =
        "SELECT DISTINCT worker_idworker,partition_idpartition "
        "FROM worker_has_partition INNER JOIN worker ON worker_has_partition.worker_idworker=worker.idworker "
        "WHERE partition_graph_idgraph=" +
        graphId + ";";

    const std::vector<vector<pair<string, string>>> &results = sqlite->runSelect(sqlStatement);

    std::map<string, std::vector<string>> partitionMap;

    for (auto i = results.begin(); i != results.end(); ++i) {
        const std::vector<pair<string, string>> &rowData = *i;

        string workerID = rowData.at(0).second;
        string partitionId = rowData.at(1).second;

        if (partitionMap.find(workerID) == partitionMap.end()) {
            std::vector<string> partitionVec;
            partitionVec.push_back(partitionId);
            partitionMap[workerID] = partitionVec;
        } else {
            partitionMap[workerID].push_back(partitionId);
        }

        sheepTriangleCount_logger.info("###SHEEP-TRIANGLE-COUNT-EXECUTOR### Getting Triangle Count : PartitionId " + partitionId);
    }

    if (results.size() > Conts::COMPOSITE_CENTRAL_STORE_WORKER_THRESHOLD) {
        isCompositeAggregation = true;
    }

    if (jasminegraph_profile == PROFILE_K8S) {
        std::unique_ptr<K8sInterface> k8sInterface(new K8sInterface());
        if (k8sInterface->getJasmineGraphConfig("auto_scaling_enabled") == "true") {
            filter_partitions(partitionMap, sqlite, graphId);
        }
    }

    std::vector<std::vector<string>> fileCombinations;
    if (isCompositeAggregation) {
        std::string aggregatorFilePath =
            Utils::getJasmineGraphProperty("org.jasminegraph.server.instance.aggregatefolder");
        std::vector<std::string> graphFiles = Utils::getListOfFilesInDirectory(aggregatorFilePath);

        std::string compositeFileNameFormat = graphId + "_compositecentralstore_";

        for (auto graphFilesIterator = graphFiles.begin(); graphFilesIterator != graphFiles.end();
             ++graphFilesIterator) {
            std::string graphFileName = *graphFilesIterator;

            if ((graphFileName.find(compositeFileNameFormat) == 0) &&
                (graphFileName.find(".gz") != std::string::npos)) {
                compositeCentralStoreFiles.push_back(graphFileName);
            }
        }
        fileCombinations = AbstractExecutor::getCombinations(compositeCentralStoreFiles);
    }

    for (auto it = partitionMap.begin(); it != partitionMap.end(); it++) {
        string worker = it->first;
        if (used_workers.find(worker) != used_workers.end()) {
            used_workers[worker]++;
        } else {
            used_workers[worker] = 1;
        }
    }

    std::map<std::string, std::string> combinationWorkerMap;
    std::unordered_map<long, std::unordered_map<long, std::unordered_set<long>>> triangleTree;
    std::mutex triangleTreeMutex;
    int partitionCount = 0;

    // Track worker information for better tracing
    std::vector<std::tuple<string, string, string>> workerTaskInfo;  // {workerID, partitionId, host}

    // Capture the master trace context for all workers
    std::string masterTraceContext = OpenTelemetryUtil::getCurrentTraceContext();

    vector<Utils::worker> workerList = Utils::getWorkerList(sqlite);
    int workerListSize = workerList.size();
    for (int i = 0; i < workerListSize; i++) {
        Utils::worker currentWorker = workerList.at(i);
        string host = currentWorker.hostname;
        string workerID = currentWorker.workerID;
        string partitionId;
        int workerPort = atoi(string(currentWorker.port).c_str());
        int workerDataPort = atoi(string(currentWorker.dataPort).c_str());
        sheepTriangleCount_logger.info("worker_" + workerID + " host=" + host + ":" + to_string(workerPort) + ":" +
                                      to_string(workerDataPort));
        const std::vector<string> &partitionList = partitionMap[workerID];
        for (auto partitionIterator = partitionList.begin(); partitionIterator != partitionList.end();
             ++partitionIterator) {
            partitionCount++;
            partitionId = *partitionIterator;
            sheepTriangleCount_logger.info("> partition" + partitionId);

            // Store worker task information for tracing
            workerTaskInfo.push_back(std::make_tuple(workerID, partitionId, host));

            {
                OTEL_TRACE_OPERATION("distribute_to_worker_" + workerID + "_partition_" + partitionId);

                // Use the static method from TriangleCountExecutor to perform the actual work
                intermRes.push_back(std::async(
                    std::launch::async, SheepTriangleCountExecutor::getSheepTriangleCount, atoi(graphId.c_str()), host,
                    workerPort, workerDataPort, atoi(partitionId.c_str()), masterIP, uniqueId,
                    isCompositeAggregation, threadPriority, fileCombinations, &combinationWorkerMap,
                    &triangleTree, &triangleTreeMutex, masterTraceContext));
            }
        }
    }

    PerformanceUtil::init();

    std::string query =
        "SELECT attempt from graph_sla INNER JOIN sla_category where graph_sla.id_sla_category=sla_category.id and "
        "graph_sla.graph_id='" +
        graphId + "' and graph_sla.partition_count='" + std::to_string(partitionCount) +
        "' and sla_category.category='" + Conts::SLA_CATEGORY::LATENCY + "' and sla_category.command='" + SHEEP_TRIANGLES +
        "';";

    const std::vector<vector<pair<string, string>>> &queryResults = perfDB->runSelect(query);

    if (queryResults.size() > 0) {
        std::string attemptString = queryResults[0][0].second;
        int calibratedAttempts = atoi(attemptString.c_str());

        if (calibratedAttempts >= Conts::MAX_SLA_CALIBRATE_ATTEMPTS) {
            canCalibrate = false;
        }
    } else {
        sheepTriangleCount_logger.log("###SHEEP-TRIANGLE-COUNT-EXECUTOR### Inserting initial record for SLA ", "info");
        Utils::updateSLAInformation(perfDB, graphId, partitionCount, 0, SHEEP_TRIANGLES, Conts::SLA_CATEGORY::LATENCY);
        statResponse.push_back(std::async(std::launch::async, AbstractExecutor::collectPerformaceData, perfDB,
                                          graphId.c_str(), SHEEP_TRIANGLES, Conts::SLA_CATEGORY::LATENCY, partitionCount,
                                          masterIP, autoCalibrate));
        isStatCollect = true;
    }

    last_exec_time = time(NULL);
    schedulerMutex.unlock();

    // Collect worker results with automatic tracing
    {
        OTEL_TRACE_OPERATION("collect_worker_results");

        int taskIndex = 0;
        for (auto &&futureCall : intermRes) {
            // Get worker information for this task
            const auto& taskInfo = workerTaskInfo[taskIndex];
            string workerID = std::get<0>(taskInfo);
            string partitionId = std::get<1>(taskInfo);
            string host = std::get<2>(taskInfo);

            {
                OTEL_TRACE_OPERATION("wait_for_worker_" + workerID + "_partition_" + partitionId + "_on_" + host);
                sheepTriangleCount_logger.info("Waiting for result from worker_" + workerID +
                                              " partition_" + partitionId +
                                              " host_" + host +
                                              " uuid=" + to_string(uniqueId));
                long worker_result = futureCall.get();
                sheepTriangleCount_logger.info("Received result " + std::to_string(worker_result) +
                                              " from worker_" + workerID +
                                              " partition_" + partitionId);

                {
                    OTEL_TRACE_OPERATION("aggregate_result_worker_" + workerID + "_partition_" + partitionId);
                    result += worker_result;
                }
            }
            taskIndex++;
        }

        // Cleanup data structures
        {
            OTEL_TRACE_OPERATION("cleanup_worker_data_structures");
            triangleTree.clear();
            combinationWorkerMap.clear();
        }
    }

    if (!isCompositeAggregation) {
        // Restore the master trace context before aggregation
        OpenTelemetryUtil::receiveAndSetTraceContext(masterTraceContext, "central store aggregation");

        OTEL_TRACE_OPERATION("central_store_aggregation");

        // Use the static aggregation method from TriangleCountExecutor
        long aggregatedTriangleCount =
            SheepTriangleCountExecutor::aggregateSheepCentralStoreTriangles(sqlite, graphId, masterIP, threadPriority, partitionMap);
        result += aggregatedTriangleCount;

        workerResponded = true;
        sheepTriangleCount_logger.log(
            "###SHEEP-TRIANGLE-COUNT-EXECUTOR### Getting Triangle Count : Completed: Triangles " + to_string(result), "info");
    }

    schedulerMutex.lock();
    for (auto it = partitionMap.begin(); it != partitionMap.end(); it++) {
        string worker = it->first;
        used_workers[worker]--;
    }
    for (auto it = used_workers.cbegin(); it != used_workers.cend();) {
        if (it->second <= 0) {
            used_workers.erase(it++);
        } else {
            it++;
        }
    }
    schedulerMutex.unlock();

    workerResponded = true;

    JobResponse jobResponse;
    jobResponse.setJobId(request.getJobId());
    jobResponse.addParameter(Conts::PARAM_KEYS::TRIANGLE_COUNT, std::to_string(result));
    
    responseVectorMutex.lock();
    responseVector.push_back(jobResponse);
    responseMap[request.getJobId()] = jobResponse;
    responseVectorMutex.unlock();

    auto end = chrono::high_resolution_clock::now();
    auto dur = end - begin;
    auto msDuration = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();

    std::string durationString = std::to_string(msDuration);

    if (canCalibrate || autoCalibrate) {
        Utils::updateSLAInformation(perfDB, graphId, partitionCount, msDuration, SHEEP_TRIANGLES,
                                    Conts::SLA_CATEGORY::LATENCY);
        isStatCollect = false;
    }

    processStatusMutex.lock();
    for (auto processCompleteIterator = processData.begin(); processCompleteIterator != processData.end();
         ++processCompleteIterator) {
        ProcessInfo processInformation = *processCompleteIterator;

        if (processInformation.id == uniqueId) {
            processData.erase(processInformation);
            break;
        }
    }
    processStatusMutex.unlock();
}

// Static helper: check if a file is accessible on a worker
static string sheepIsFileAccessibleToWorker(std::string graphId, std::string partitionId,
                                           std::string aggregatorHostName, std::string aggregatorPort,
                                           std::string masterIP, std::string fileType, std::string fileName) {
    int sockfd;
    char data[INSTANCE_DATA_LENGTH + 1];
    struct sockaddr_in serv_addr;
    struct hostent *server;
    string isFileAccessible = "false";

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        sheepTriangleCount_logger.error("Cannot create socket");
        return "false";
    }

    server = gethostbyname(aggregatorHostName.c_str());
    if (server == NULL) {
        sheepTriangleCount_logger.error("ERROR, no host named " + aggregatorHostName);
        close(sockfd);
        return "false";
    }

    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(atoi(aggregatorPort.c_str()));
    if (Utils::connect_wrapper(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        sheepTriangleCount_logger.error("ERROR connecting");
        close(sockfd);
        return "false";
    }

    int result_wr = write(sockfd, JasmineGraphInstanceProtocol::HANDSHAKE.c_str(),
                          JasmineGraphInstanceProtocol::HANDSHAKE.size());
    if (result_wr < 0) {
        sheepTriangleCount_logger.log("Error writing to socket", "error");
    }

    string response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
    if (response.compare(JasmineGraphInstanceProtocol::HANDSHAKE_OK) == 0) {
        result_wr = write(sockfd, masterIP.c_str(), masterIP.size());
        if (result_wr < 0) {
            sheepTriangleCount_logger.log("Error writing to socket", "error");
        }

        response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
        if (response.compare(JasmineGraphInstanceProtocol::HOST_OK) != 0) {
            sheepTriangleCount_logger.log("Received : " + response, "error");
        }

        result_wr = write(sockfd, JasmineGraphInstanceProtocol::CHECK_FILE_ACCESSIBLE.c_str(),
                          JasmineGraphInstanceProtocol::CHECK_FILE_ACCESSIBLE.size());
        if (result_wr < 0) {
            sheepTriangleCount_logger.log("Error writing to socket", "error");
        }

        response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
        if (response.compare(JasmineGraphInstanceProtocol::SEND_FILE_TYPE) == 0) {
            result_wr = write(sockfd, fileType.c_str(), fileType.size());
            if (result_wr < 0) {
                sheepTriangleCount_logger.log("Error writing to socket", "error");
            }

            response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
            if (response.compare(JasmineGraphInstanceProtocol::SEND_FILE_NAME) == 0) {
                if (fileType == JasmineGraphInstanceProtocol::FILE_TYPE_CENTRALSTORE_AGGREGATE) {
                    std::string centralStoreFileName = graphId + "_centralstore_" + partitionId;
                    result_wr = write(sockfd, centralStoreFileName.c_str(), centralStoreFileName.size());
                } else {
                    result_wr = write(sockfd, fileName.c_str(), fileName.size());
                }
                if (result_wr < 0) {
                    sheepTriangleCount_logger.log("Error writing to socket", "error");
                }

                response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
                isFileAccessible = response;
            }
        }
    }

    Utils::send_str_wrapper(sockfd, JasmineGraphInstanceProtocol::CLOSE);
    close(sockfd);
    return isFileAccessible;
}

// Independent implementation: sends SHEEP_TRIANGLES protocol to workers
long SheepTriangleCountExecutor::getSheepTriangleCount(
    int graphId, std::string host, int port, int dataPort, int partitionId, std::string masterIP, int uniqueId,
    bool isCompositeAggregation, int threadPriority, std::vector<std::vector<string>> fileCombinations,
    std::map<std::string, std::string> *combinationWorkerMap_p,
    std::unordered_map<long, std::unordered_map<long, std::unordered_set<long>>> *triangleTree_p,
    std::mutex *triangleTreeMutex_p, const std::string& masterTraceContext) {

    int sockfd;
    char data[INSTANCE_DATA_LENGTH + 1];
    struct sockaddr_in serv_addr;
    struct hostent *server;
    long triangleCount = 0;
    int result_wr;
    string response;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        sheepTriangleCount_logger.error("Cannot create socket");
        return 0;
    }

    if (host.find('@') != std::string::npos) {
        host = Utils::split(host, '@')[1];
    }

    sheepTriangleCount_logger.log("###SHEEP-TRIANGLE-COUNT### Get Host By Name : " + host, "info");

    server = gethostbyname(host.c_str());
    if (server == NULL) {
        sheepTriangleCount_logger.error("ERROR, no host named " + host);
        return 0;
    }

    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    if (Utils::connect_wrapper(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        sheepTriangleCount_logger.error("ERROR connecting");
        return 0;
    }

    // Protocol handshake
    result_wr = write(sockfd, JasmineGraphInstanceProtocol::HANDSHAKE.c_str(),
                      JasmineGraphInstanceProtocol::HANDSHAKE.size());
    if (result_wr < 0) {
        sheepTriangleCount_logger.log("Error writing to socket", "error");
    }

    sheepTriangleCount_logger.log("Sent : " + JasmineGraphInstanceProtocol::HANDSHAKE, "info");
    response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);

    if (response.compare(JasmineGraphInstanceProtocol::HANDSHAKE_OK) == 0) {
        sheepTriangleCount_logger.log("Received : " + JasmineGraphInstanceProtocol::HANDSHAKE_OK, "info");
        result_wr = write(sockfd, masterIP.c_str(), masterIP.size());
        if (result_wr < 0) {
            sheepTriangleCount_logger.log("Error writing to socket", "error");
        }
        sheepTriangleCount_logger.log("Sent : " + masterIP, "info");

        response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
        if (response.compare(JasmineGraphInstanceProtocol::HOST_OK) == 0) {
            sheepTriangleCount_logger.log("Received : " + JasmineGraphInstanceProtocol::HOST_OK, "info");
        } else {
            sheepTriangleCount_logger.log("Received : " + response, "error");
        }

        // Send SHEEP_TRIANGLES protocol command (NOT TRIANGLES)
        result_wr = write(sockfd, JasmineGraphInstanceProtocol::SHEEP_TRIANGLES.c_str(),
                          JasmineGraphInstanceProtocol::SHEEP_TRIANGLES.size());
        if (result_wr < 0) {
            sheepTriangleCount_logger.log("Error writing to socket", "error");
        }
        sheepTriangleCount_logger.log("Sent : " + JasmineGraphInstanceProtocol::SHEEP_TRIANGLES, "info");

        response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
        if (response.compare(JasmineGraphInstanceProtocol::OK) == 0) {
            sheepTriangleCount_logger.log("Received : " + JasmineGraphInstanceProtocol::OK, "info");
            result_wr = write(sockfd, std::to_string(graphId).c_str(), std::to_string(graphId).size());
            if (result_wr < 0) {
                sheepTriangleCount_logger.log("Error writing to socket", "error");
            }
            sheepTriangleCount_logger.log("Sent : Graph ID " + std::to_string(graphId), "info");
            response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
        }

        if (response.compare(JasmineGraphInstanceProtocol::OK) == 0) {
            sheepTriangleCount_logger.log("Received : " + JasmineGraphInstanceProtocol::OK, "info");
            result_wr = write(sockfd, std::to_string(partitionId).c_str(), std::to_string(partitionId).size());
            if (result_wr < 0) {
                sheepTriangleCount_logger.log("Error writing to socket", "error");
            }
            sheepTriangleCount_logger.log("Sent : Partition ID " + std::to_string(partitionId), "info");
            response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
        }

        if (response.compare(JasmineGraphInstanceProtocol::OK) == 0) {
            sheepTriangleCount_logger.log("Received : " + JasmineGraphInstanceProtocol::OK, "info");
            result_wr = write(sockfd, std::to_string(threadPriority).c_str(), std::to_string(threadPriority).size());
            if (result_wr < 0) {
                sheepTriangleCount_logger.log("Error writing to socket", "error");
            }
            sheepTriangleCount_logger.log("Sent : Thread Priority " + std::to_string(threadPriority), "info");

            response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);

            // Send trace context for distributed tracing
            if (response.compare(JasmineGraphInstanceProtocol::OK) == 0) {
                sheepTriangleCount_logger.log("Received : " + JasmineGraphInstanceProtocol::OK, "info");

                std::string traceContext = masterTraceContext;
                if (traceContext.empty()) {
                    traceContext = "NO_TRACE_CONTEXT";
                }

                result_wr = write(sockfd, traceContext.c_str(), traceContext.size());
                if (result_wr < 0) {
                    sheepTriangleCount_logger.log("Error writing trace context to socket", "error");
                }

                sheepTriangleCount_logger.log("Sent : Trace Context " + traceContext, "info");
                response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
            }

            sheepTriangleCount_logger.log("Got response : |" + response + "|", "info");
            triangleCount = atol(response.c_str());
        }

        if (isCompositeAggregation) {
            sheepTriangleCount_logger.log("###COMPOSITE### Started Composite aggregation ", "info");
            for (int combinationIndex = 0; combinationIndex < fileCombinations.size(); ++combinationIndex) {
                const std::vector<string> &fileList = fileCombinations.at(combinationIndex);
                std::set<string> partitionIdSet;
                std::set<string> partitionSet;
                std::set<string> transferRequireFiles;
                std::string combinationKey = "";
                std::string availableFiles = "";
                std::string transferredFiles = "";
                bool isAggregateValid = false;

                for (auto listIterator = fileList.begin(); listIterator != fileList.end(); ++listIterator) {
                    std::string fileName = *listIterator;
                    size_t lastIndex = fileName.find_last_of(".");
                    string rawFileName = fileName.substr(0, lastIndex);
                    const std::vector<std::string> &fileNameParts = Utils::split(rawFileName, '_');

                    for (int index = 2; index < fileNameParts.size(); ++index) {
                        partitionSet.insert(fileNameParts[index]);
                    }
                }

                if (partitionSet.find(std::to_string(partitionId)) == partitionSet.end()) {
                    continue;
                }

                for (auto fileListIterator = fileList.begin(); fileListIterator != fileList.end(); ++fileListIterator) {
                    std::string fileName = *fileListIterator;
                    bool isTransferRequired = true;

                    combinationKey = fileName + ":" + combinationKey;

                    size_t lastindex = fileName.find_last_of(".");
                    string rawFileName = fileName.substr(0, lastindex);
                    std::vector<std::string> fileNameParts = Utils::split(rawFileName, '_');

                    for (int index = 2; index < fileNameParts.size(); ++index) {
                        if (fileNameParts[index] == std::to_string(partitionId)) {
                            isTransferRequired = false;
                        }
                        partitionIdSet.insert(fileNameParts[index]);
                    }

                    if (isTransferRequired) {
                        transferRequireFiles.insert(fileName);
                        transferredFiles = fileName + ":" + transferredFiles;
                    } else {
                        availableFiles = fileName + ":" + availableFiles;
                    }
                }

                std::string adjustedAvailableFiles = availableFiles.substr(0, availableFiles.size() - 1);
                std::string adjustedTransferredFile = transferredFiles.substr(0, transferredFiles.size() - 1);

                fileCombinationMutex.lock();
                std::map<std::string, std::string> &combinationWorkerMap = *combinationWorkerMap_p;
                if (combinationWorkerMap.find(combinationKey) == combinationWorkerMap.end()) {
                    if (partitionIdSet.find(std::to_string(partitionId)) != partitionIdSet.end()) {
                        combinationWorkerMap[combinationKey] = std::to_string(partitionId);
                        isAggregateValid = true;
                    }
                }
                fileCombinationMutex.unlock();

                if (isAggregateValid) {
                    for (auto transferRequireFileIterator = transferRequireFiles.begin();
                         transferRequireFileIterator != transferRequireFiles.end(); ++transferRequireFileIterator) {
                        std::string transferFileName = *transferRequireFileIterator;
                        std::string fileAccessible = sheepIsFileAccessibleToWorker(
                            std::to_string(graphId), std::string(), host, std::to_string(port), masterIP,
                            JasmineGraphInstanceProtocol::FILE_TYPE_CENTRALSTORE_COMPOSITE, transferFileName);

                        if (fileAccessible.compare("false") == 0) {
                            SheepTriangleCountExecutor::copyCompositeCentralStoreToAggregator(
                                host, std::to_string(port), std::to_string(dataPort), transferFileName, masterIP);
                        }
                    }

                    sheepTriangleCount_logger.log("###COMPOSITE### Retrieved Composite triangle list ", "debug");

                    const auto &triangles = SheepTriangleCountExecutor::countCompositeCentralStoreTriangles(
                        host, std::to_string(port), adjustedTransferredFile, masterIP, adjustedAvailableFiles,
                        threadPriority);
                    if (triangles.size() > 0) {
                        // Inline triangle tree update
                        std::mutex &triangleTreeMutex = *triangleTreeMutex_p;
                        const std::lock_guard<std::mutex> lock1(triangleTreeMutex);
                        auto &triangleTree = *triangleTree_p;

                        for (auto triangleIterator = triangles.begin(); triangleIterator != triangles.end();
                             ++triangleIterator) {
                            std::string triangle = *triangleIterator;
                            if (!triangle.empty() && triangle != "NILL") {
                                std::vector<std::string> triangleVertexList = Utils::split(triangle, ',');
                                long vertexOne = std::atol(triangleVertexList.at(0).c_str());
                                long vertexTwo = std::atol(triangleVertexList.at(1).c_str());
                                long vertexThree = std::atol(triangleVertexList.at(2).c_str());

                                auto &itemRes = triangleTree[vertexOne];
                                auto itemResIterator = itemRes.find(vertexTwo);
                                if (itemResIterator != itemRes.end()) {
                                    auto &set2 = itemResIterator->second;
                                    if (set2.find(vertexThree) == set2.end()) {
                                        set2.insert(vertexThree);
                                        triangleCount++;
                                    }
                                } else {
                                    triangleTree[vertexOne][vertexTwo].insert(vertexThree);
                                    triangleCount++;
                                }
                            }
                        }
                    }
                }
            }
        }

        sheepTriangleCount_logger.info("###COMPOSITE### Returning Total Sheep Triangles from executor ");
        Utils::send_str_wrapper(sockfd, JasmineGraphInstanceProtocol::CLOSE);
        close(sockfd);
        return triangleCount;

    } else {
        sheepTriangleCount_logger.log("There was an error in the upload process and the response is :: " + response,
                                     "error");
    }
    Utils::send_str_wrapper(sockfd, JasmineGraphInstanceProtocol::CLOSE);
    close(sockfd);
    return 0;
}

std::string SheepTriangleCountExecutor::copyCompositeCentralStoreToAggregator(std::string aggregatorHostName,
                                                                              std::string aggregatorPort,
                                                                              std::string aggregatorDataPort,
                                                                              std::string fileName,
                                                                              std::string masterIP) {
    // Use same protocol as TriangleCountExecutor - this is generic file transfer infrastructure
    int sockfd;
    char data[INSTANCE_DATA_LENGTH + 1];
    struct sockaddr_in serv_addr;
    struct hostent *server;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        sheepTriangleCount_logger.error("Cannot create socket");
        return "";
    }

    if (aggregatorHostName.find('@') != std::string::npos) {
        aggregatorHostName = Utils::split(aggregatorHostName, '@')[1];
    }

    server = gethostbyname(aggregatorHostName.c_str());
    if (server == NULL) {
        sheepTriangleCount_logger.error("ERROR, no host named " + aggregatorHostName);
        return "";
    }

    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(atoi(aggregatorPort.c_str()));
    if (Utils::connect_wrapper(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        sheepTriangleCount_logger.error("ERROR connecting");
        return "";
    }

    int result_wr = write(sockfd, JasmineGraphInstanceProtocol::HANDSHAKE.c_str(),
                          JasmineGraphInstanceProtocol::HANDSHAKE.size());
    if (result_wr < 0) {
        sheepTriangleCount_logger.log("Error writing to socket", "error");
    }

    string response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
    if (response.compare(JasmineGraphInstanceProtocol::HANDSHAKE_OK) == 0) {
        result_wr = write(sockfd, masterIP.c_str(), masterIP.size());
        if (result_wr < 0) {
            sheepTriangleCount_logger.log("Error writing to socket", "error");
        }

        response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
        if (response.compare(JasmineGraphInstanceProtocol::HOST_OK) != 0) {
            sheepTriangleCount_logger.log("Received : " + response, "error");
        }

        result_wr = write(sockfd, JasmineGraphInstanceProtocol::SEND_COMPOSITE_CENTRALSTORE_TO_AGGREGATOR.c_str(),
                          JasmineGraphInstanceProtocol::SEND_COMPOSITE_CENTRALSTORE_TO_AGGREGATOR.size());
        if (result_wr < 0) {
            sheepTriangleCount_logger.log("Error writing to socket", "error");
        }

        response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
        if (response.compare(JasmineGraphInstanceProtocol::SEND_FILE_NAME) == 0) {
            result_wr = write(sockfd, fileName.c_str(), fileName.size());
            if (result_wr < 0) {
                sheepTriangleCount_logger.log("Error writing to socket", "error");
            }

            response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
            if (response.compare(JasmineGraphInstanceProtocol::SEND_FILE_LEN) == 0) {
                sheepTriangleCount_logger.log("Received : " + JasmineGraphInstanceProtocol::SEND_FILE_LEN, "info");
                std::string instanceDataFolderLocation =
                    Utils::getJasmineGraphProperty("org.jasminegraph.server.instance.datafolder");
                std::string aggregateStoreFileName = instanceDataFolderLocation + "/" + fileName;

                std::ifstream file(aggregateStoreFileName, std::ios::binary | std::ios::ate);
                int fileSize = file.tellg();
                file.close();

                result_wr =
                    write(sockfd, std::to_string(fileSize).c_str(), std::to_string(fileSize).size());
                if (result_wr < 0) {
                    sheepTriangleCount_logger.log("Error writing to socket", "error");
                }

                response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
                if (response.compare(JasmineGraphInstanceProtocol::SEND_FILE_CONT) == 0) {
                    sheepTriangleCount_logger.log("Received : " + JasmineGraphInstanceProtocol::SEND_FILE_CONT,
                                                 "info");
                    sheepTriangleCount_logger.log("Going to send file: " + aggregateStoreFileName, "info");
                    Utils::sendFileThroughService(aggregatorHostName, atoi(aggregatorDataPort.c_str()),
                                                 fileName, aggregateStoreFileName);
                }
            }

            int count = 0;
            while (true) {
                result_wr = write(sockfd, JasmineGraphInstanceProtocol::FILE_RECV_CHK.c_str(),
                                  JasmineGraphInstanceProtocol::FILE_RECV_CHK.size());
                if (result_wr < 0) {
                    sheepTriangleCount_logger.log("Error writing to socket", "error");
                }

                response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
                if (response.compare(JasmineGraphInstanceProtocol::FILE_RECV_WAIT) == 0) {
                    sheepTriangleCount_logger.log("Received : " + JasmineGraphInstanceProtocol::FILE_RECV_WAIT,
                                                 "info");
                    sleep(1);
                    count++;
                    if (count >= 10) {
                        break;
                    }
                } else if (response.compare(JasmineGraphInstanceProtocol::FILE_ACK) == 0) {
                    sheepTriangleCount_logger.log("Received : " + JasmineGraphInstanceProtocol::FILE_ACK, "info");
                    break;
                }
            }
        }
    }

    Utils::send_str_wrapper(sockfd, JasmineGraphInstanceProtocol::CLOSE);
    close(sockfd);
    return response;
}

std::vector<string> SheepTriangleCountExecutor::countCompositeCentralStoreTriangles(
    std::string aggregatorHostName, std::string aggregatorPort, std::string compositeCentralStoreFileList,
    std::string masterIP, std::string availableFileList, int threadPriority) {
    int sockfd;
    char data[INSTANCE_DATA_LENGTH + 1];
    struct sockaddr_in serv_addr;
    struct hostent *server;
    std::vector<string> triangleList;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        sheepTriangleCount_logger.error("Cannot create socket");
        return triangleList;
    }

    if (aggregatorHostName.find('@') != std::string::npos) {
        aggregatorHostName = Utils::split(aggregatorHostName, '@')[1];
    }

    server = gethostbyname(aggregatorHostName.c_str());
    if (server == NULL) {
        sheepTriangleCount_logger.error("ERROR, no host named " + aggregatorHostName);
        return triangleList;
    }

    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(atoi(aggregatorPort.c_str()));
    if (Utils::connect_wrapper(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        sheepTriangleCount_logger.error("ERROR connecting");
        return triangleList;
    }

    int result_wr = write(sockfd, JasmineGraphInstanceProtocol::HANDSHAKE.c_str(),
                          JasmineGraphInstanceProtocol::HANDSHAKE.size());
    if (result_wr < 0) {
        sheepTriangleCount_logger.log("Error writing to socket", "error");
    }

    string response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
    if (response.compare(JasmineGraphInstanceProtocol::HANDSHAKE_OK) == 0) {
        result_wr = write(sockfd, masterIP.c_str(), masterIP.size());
        if (result_wr < 0) {
            sheepTriangleCount_logger.log("Error writing to socket", "error");
        }

        response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
        if (response.compare(JasmineGraphInstanceProtocol::HOST_OK) != 0) {
            sheepTriangleCount_logger.log("Received : " + response, "error");
        }

        result_wr = write(sockfd, JasmineGraphInstanceProtocol::AGGREGATE_COMPOSITE_CENTRALSTORE_TRIANGLES.c_str(),
                          JasmineGraphInstanceProtocol::AGGREGATE_COMPOSITE_CENTRALSTORE_TRIANGLES.size());
        if (result_wr < 0) {
            sheepTriangleCount_logger.log("Error writing to socket", "error");
        }

        response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
        if (response.compare(JasmineGraphInstanceProtocol::OK) == 0) {
            result_wr = write(sockfd, compositeCentralStoreFileList.c_str(), compositeCentralStoreFileList.size());
            if (result_wr < 0) {
                sheepTriangleCount_logger.log("Error writing to socket", "error");
            }

            response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
            if (response.compare(JasmineGraphInstanceProtocol::OK) == 0) {
                result_wr = write(sockfd, availableFileList.c_str(), availableFileList.size());
                if (result_wr < 0) {
                    sheepTriangleCount_logger.log("Error writing to socket", "error");
                }

                response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
                if (response.compare(JasmineGraphInstanceProtocol::OK) == 0) {
                    result_wr = write(sockfd, std::to_string(threadPriority).c_str(),
                                     std::to_string(threadPriority).size());
                    if (result_wr < 0) {
                        sheepTriangleCount_logger.log("Error writing to socket", "error");
                    }

                    response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
                    triangleList = Utils::split(response, ':');
                }
            }
        }
    }

    Utils::send_str_wrapper(sockfd, JasmineGraphInstanceProtocol::CLOSE);
    close(sockfd);
    return triangleList;
}

std::string SheepTriangleCountExecutor::copyCentralStoreToAggregator(std::string aggregatorHostName,
                                                                     std::string aggregatorPort,
                                                                     std::string aggregatorDataPort,
                                                                     int graphId,
                                                                     int partitionId,
                                                                     std::string masterIP) {
    int sockfd;
    char data[INSTANCE_DATA_LENGTH + 1];
    struct sockaddr_in serv_addr;
    struct hostent *server;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        sheepTriangleCount_logger.error("Cannot create socket");
        return "";
    }

    if (aggregatorHostName.find('@') != std::string::npos) {
        aggregatorHostName = Utils::split(aggregatorHostName, '@')[1];
    }

    server = gethostbyname(aggregatorHostName.c_str());
    if (server == NULL) {
        sheepTriangleCount_logger.error("ERROR, no host named " + aggregatorHostName);
        return "";
    }

    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(atoi(aggregatorPort.c_str()));
    if (Utils::connect_wrapper(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        sheepTriangleCount_logger.error("ERROR connecting");
        return "";
    }

    int result_wr = write(sockfd, JasmineGraphInstanceProtocol::HANDSHAKE.c_str(),
                          JasmineGraphInstanceProtocol::HANDSHAKE.size());
    if (result_wr < 0) {
        sheepTriangleCount_logger.log("Error writing to socket", "error");
    }

    string response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
    if (response.compare(JasmineGraphInstanceProtocol::HANDSHAKE_OK) == 0) {
        result_wr = write(sockfd, masterIP.c_str(), masterIP.size());
        if (result_wr < 0) {
            sheepTriangleCount_logger.log("Error writing to socket", "error");
        }

        response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
        if (response.compare(JasmineGraphInstanceProtocol::HOST_OK) != 0) {
            sheepTriangleCount_logger.log("Received : " + response, "error");
        }

        result_wr = write(sockfd, JasmineGraphInstanceProtocol::SEND_CENTRALSTORE_TO_AGGREGATOR.c_str(),
                          JasmineGraphInstanceProtocol::SEND_CENTRALSTORE_TO_AGGREGATOR.size());
        if (result_wr < 0) {
            sheepTriangleCount_logger.log("Error writing to socket", "error");
        }

        response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
        if (response.compare(JasmineGraphInstanceProtocol::SEND_FILE_NAME) == 0) {
            std::string centralStoreFileName =
                std::to_string(graphId) + "_centralstore_" + std::to_string(partitionId);
            result_wr = write(sockfd, centralStoreFileName.c_str(), centralStoreFileName.size());
            if (result_wr < 0) {
                sheepTriangleCount_logger.log("Error writing to socket", "error");
            }

            response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
            if (response.compare(JasmineGraphInstanceProtocol::SEND_FILE_LEN) == 0) {
                std::string instanceDataFolderLocation =
                    Utils::getJasmineGraphProperty("org.jasminegraph.server.instance.datafolder");
                std::string aggregateStoreFileName =
                    instanceDataFolderLocation + "/" + centralStoreFileName + ".gz";

                std::ifstream file(aggregateStoreFileName, std::ios::binary | std::ios::ate);
                int fileSize = file.tellg();
                file.close();

                result_wr = write(sockfd, std::to_string(fileSize).c_str(), std::to_string(fileSize).size());
                if (result_wr < 0) {
                    sheepTriangleCount_logger.log("Error writing to socket", "error");
                }

                response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
                if (response.compare(JasmineGraphInstanceProtocol::SEND_FILE_CONT) == 0) {
                    sheepTriangleCount_logger.log("Going to send file: " + aggregateStoreFileName, "info");
                    Utils::sendFileThroughService(aggregatorHostName, atoi(aggregatorDataPort.c_str()),
                                                 centralStoreFileName + ".gz", aggregateStoreFileName);
                }
            }

            int count = 0;
            while (true) {
                result_wr = write(sockfd, JasmineGraphInstanceProtocol::FILE_RECV_CHK.c_str(),
                                  JasmineGraphInstanceProtocol::FILE_RECV_CHK.size());
                if (result_wr < 0) {
                    sheepTriangleCount_logger.log("Error writing to socket", "error");
                }

                response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
                if (response.compare(JasmineGraphInstanceProtocol::FILE_RECV_WAIT) == 0) {
                    sleep(1);
                    count++;
                    if (count >= 10) {
                        break;
                    }
                } else if (response.compare(JasmineGraphInstanceProtocol::FILE_ACK) == 0) {
                    break;
                }
            }
        }
    }

    Utils::send_str_wrapper(sockfd, JasmineGraphInstanceProtocol::CLOSE);
    close(sockfd);
    return response;
}

// Independent aggregation of central store triangles for sheep-partitioned graphs
long SheepTriangleCountExecutor::aggregateSheepCentralStoreTriangles(
    SQLiteDBInterface *sqlite, std::string graphId, std::string masterIP, int threadPriority,
    const std::map<string, std::vector<string>> &partitionMap) {
    OTEL_TRACE_FUNCTION();

    vector<string> partitionsVector;
    std::map<string, string> partitionWorkerMap;  // partition_id => worker_id
    for (auto it = partitionMap.begin(); it != partitionMap.end(); it++) {
        const auto &parts = it->second;
        string worker = it->first;
        for (auto partsIt = parts.begin(); partsIt != parts.end(); partsIt++) {
            string partition = *partsIt;
            partitionWorkerMap[partition] = worker;
            partitionsVector.push_back(partition);
        }
    }

    const std::vector<std::vector<string>> &partitionCombinations = AbstractExecutor::getCombinations(partitionsVector);
    std::map<string, int> workerWeightMap;
    std::vector<std::future<string>> triangleCountResponse;
    std::string result = "";
    long aggregatedTriangleCount = 0;

    const std::vector<vector<pair<string, string>>> &workerDataResult =
        sqlite->runSelect("SELECT DISTINCT idworker,ip,server_port,server_data_port FROM worker;");
    map<string, vector<string>> workerDataMap;  // worker_id => [ip,port,data_port]
    for (auto it = workerDataResult.begin(); it != workerDataResult.end(); it++) {
        const auto &ipPortDport = *it;
        string id = ipPortDport[0].second;
        string ip = ipPortDport[1].second;
        string port = ipPortDport[2].second;
        string dport = ipPortDport[3].second;
        workerDataMap[id] = {ip, port, dport};
    }

    for (auto partitonCombinationsIterator = partitionCombinations.begin();
         partitonCombinationsIterator != partitionCombinations.end(); partitonCombinationsIterator++) {
        const std::vector<string> &partitionCombination = *partitonCombinationsIterator;
        std::vector<std::future<string>> remoteGraphCopyResponse;
        int minimumWeight = 0;
        std::string minWeightWorker;
        std::string minWeightWorkerPartition;

        for (auto partCombinationIterator = partitionCombination.begin();
             partCombinationIterator != partitionCombination.end(); partCombinationIterator++) {
            string part = *partCombinationIterator;
            string workerId = partitionWorkerMap[part];
            auto workerWeightMapIterator = workerWeightMap.find(workerId);
            if (workerWeightMapIterator != workerWeightMap.end()) {
                int weight = workerWeightMapIterator->second;
                if (minimumWeight == 0 || minimumWeight > weight) {
                    minimumWeight = weight + 1;
                    minWeightWorker = workerId;
                    minWeightWorkerPartition = part;
                }
            } else {
                minimumWeight = 1;
                minWeightWorker = workerId;
                minWeightWorkerPartition = part;
            }
        }
        workerWeightMap[minWeightWorker] = minimumWeight;

        const auto &workerData = workerDataMap[minWeightWorker];
        std::string aggregatorIp = workerData[0];
        std::string aggregatorPort = workerData[1];
        std::string aggregatorDataPort = workerData[2];

        std::string aggregatorPartitionId = minWeightWorkerPartition;

        std::string partitionIdList = "";
        for (auto partitionCombinationIterator = partitionCombination.begin();
             partitionCombinationIterator != partitionCombination.end(); ++partitionCombinationIterator) {
            string part = *partitionCombinationIterator;

            if (part != minWeightWorkerPartition) {
                partitionIdList += part + ",";
            }
            if (partitionWorkerMap[part] != minWeightWorker) {
                std::string centralStoreAvailable = sheepIsFileAccessibleToWorker(
                    graphId, part, aggregatorIp, aggregatorPort, masterIP,
                    JasmineGraphInstanceProtocol::FILE_TYPE_CENTRALSTORE_AGGREGATE, std::string());

                if (centralStoreAvailable.compare("false") == 0) {
                    remoteGraphCopyResponse.push_back(std::async(
                        std::launch::async, SheepTriangleCountExecutor::copyCentralStoreToAggregator, aggregatorIp,
                        aggregatorPort, aggregatorDataPort, atoi(graphId.c_str()), atoi(part.c_str()), masterIP));
                }
            }
        }

        for (auto &&futureCallCopy : remoteGraphCopyResponse) {
            futureCallCopy.get();
        }

        std::string adjustedPartitionIdList = partitionIdList.substr(0, partitionIdList.size() - 1);

        std::string currentTraceContext = OpenTelemetryUtil::getCurrentTraceContext();

        triangleCountResponse.push_back(std::async(
            std::launch::async, SheepTriangleCountExecutor::countSheepCentralStoreTriangles, aggregatorPort,
            aggregatorIp, aggregatorPartitionId, adjustedPartitionIdList, graphId, masterIP, threadPriority,
            currentTraceContext));
    }

    for (auto &&futureCall : triangleCountResponse) {
        result = result + ":" + futureCall.get();
    }

    const std::vector<std::string> &triangles = Utils::split(result, ':');
    std::set<std::string> uniqueTriangleSet;
    for (auto triangleIterator = triangles.begin(); triangleIterator != triangles.end(); ++triangleIterator) {
        std::string triangle = *triangleIterator;
        if (!triangle.empty() && triangle != "NILL") {
            uniqueTriangleSet.insert(triangle);
        }
    }

    aggregatedTriangleCount = uniqueTriangleSet.size();
    uniqueTriangleSet.clear();

    return aggregatedTriangleCount;
}

// Independent central store triangle counting
string SheepTriangleCountExecutor::countSheepCentralStoreTriangles(
    std::string aggregatorPort, std::string host, std::string partitionId, std::string partitionIdList,
    std::string graphId, std::string masterIP, int threadPriority, std::string traceContext) {
    int sockfd;
    char data[INSTANCE_DATA_LENGTH + 1];
    struct sockaddr_in serv_addr;
    struct hostent *server;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        sheepTriangleCount_logger.error("Cannot create socket");
        return "";
    }

    if (host.find('@') != std::string::npos) {
        host = Utils::split(host, '@')[1];
    }

    server = gethostbyname(host.c_str());
    if (server == NULL) {
        sheepTriangleCount_logger.error("ERROR, no host named " + host);
        return "";
    }

    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(atoi(aggregatorPort.c_str()));
    if (Utils::connect_wrapper(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        sheepTriangleCount_logger.error("ERROR connecting");
        return "";
    }

    int result_wr = write(sockfd, JasmineGraphInstanceProtocol::HANDSHAKE.c_str(),
                          JasmineGraphInstanceProtocol::HANDSHAKE.size());
    if (result_wr < 0) {
        sheepTriangleCount_logger.log("Error writing to socket", "error");
    }

    string response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
    string result = "";

    if (response.compare(JasmineGraphInstanceProtocol::HANDSHAKE_OK) == 0) {
        result_wr = write(sockfd, masterIP.c_str(), masterIP.size());
        if (result_wr < 0) {
            sheepTriangleCount_logger.log("Error writing to socket", "error");
        }

        response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
        if (response.compare(JasmineGraphInstanceProtocol::HOST_OK) != 0) {
            sheepTriangleCount_logger.log("Received : " + response, "error");
        }

        result_wr = write(sockfd, JasmineGraphInstanceProtocol::AGGREGATE_CENTRALSTORE_TRIANGLES.c_str(),
                          JasmineGraphInstanceProtocol::AGGREGATE_CENTRALSTORE_TRIANGLES.size());
        if (result_wr < 0) {
            sheepTriangleCount_logger.log("Error writing to socket", "error");
        }

        response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
        if (response.compare(JasmineGraphInstanceProtocol::OK) == 0) {
            result_wr = write(sockfd, graphId.c_str(), graphId.size());
            if (result_wr < 0) {
                sheepTriangleCount_logger.log("Error writing to socket", "error");
            }

            response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
            if (response.compare(JasmineGraphInstanceProtocol::OK) == 0) {
                result_wr = write(sockfd, partitionId.c_str(), partitionId.size());
                if (result_wr < 0) {
                    sheepTriangleCount_logger.log("Error writing to socket", "error");
                }

                response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
                if (response.compare(JasmineGraphInstanceProtocol::OK) == 0) {
                    result_wr = write(sockfd, partitionIdList.c_str(), partitionIdList.size());
                    if (result_wr < 0) {
                        sheepTriangleCount_logger.log("Error writing to socket", "error");
                    }

                    response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
                    if (response.compare(JasmineGraphInstanceProtocol::OK) == 0) {
                        result_wr = write(sockfd, std::to_string(threadPriority).c_str(),
                                         std::to_string(threadPriority).size());
                        if (result_wr < 0) {
                            sheepTriangleCount_logger.log("Error writing to socket", "error");
                        }

                        response = Utils::read_str_trim_wrapper(sockfd, data, INSTANCE_DATA_LENGTH);
                        result = response;
                    }
                }
            }
        }
    }

    Utils::send_str_wrapper(sockfd, JasmineGraphInstanceProtocol::CLOSE);
    close(sockfd);
    return result;
}
