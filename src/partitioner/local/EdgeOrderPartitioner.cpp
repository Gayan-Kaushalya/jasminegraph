/**
 * Copyright 2024 JasmineGraph Team
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "EdgeOrderPartitioner.h"

#include <flatbuffers/flatbuffers.h>
#include <algorithm>
#include <queue>
#include <unordered_set>
#include <cmath>
#include <thread>

#include "../../util/Conts.h"
#include "../../util/logger/Logger.h"
#include "../../util/dbutil/GetConfig.h"
#include "../../centralstore/JasmineGraphHashMapCentralStore.h"
#include "../../localstore/JasmineGraphHashMapLocalStore.h"
#include "RDFParser.h"

extern Logger partitioner_logger;
extern std::mutex partFileMutex;
extern std::mutex masterFileMutex;
extern std::mutex partAttrFileMutex;
extern std::mutex masterAttrFileMutex;
extern std::mutex dbLock;

EdgeOrderPartitioner::EdgeOrderPartitioner(SQLiteDBInterface *sqlite) {
    this->sqlite = sqlite;
    this->edgeCount = 0;
    this->vertexCount = 0;
    this->largestVertex = 0;
    this->smallestVertex = std::numeric_limits<int>::max();
    this->zeroflag = false;
    this->nParts = 0;
}

void EdgeOrderPartitioner::loadDataSet(string inputFilePath, int graphID) {
    partitioner_logger.log("Processing dataset for edge-order partitioning", "info");
    this->graphID = graphID;
    this->outputFilePath = Utils::getHomeDir() + "/.jasminegraph/tmp/" + std::to_string(this->graphID);

    Utils::createDirectory(Utils::getHomeDir() + "/.jasminegraph/tmp");
    Utils::createDirectory(this->outputFilePath);

    std::ifstream dbFile;
    dbFile.open(inputFilePath, std::ios::binary | std::ios::in);

    if (!dbFile.is_open()) {
        partitioner_logger.error("Failed to open file: " + inputFilePath);
        return;
    }

    int firstVertex = -1;
    int secondVertex = -1;
    string line;
    char splitter = ' ';

    std::getline(dbFile, line);

    // Detect delimiter
    if (!line.empty()) {
        if (line.find(" ") != std::string::npos) {
            splitter = ' ';
        } else if (line.find('\t') != std::string::npos) {
            splitter = '\t';
        } else if (line.find(",") != std::string::npos) {
            splitter = ',';
        }
    }

    while (!line.empty()) {
        // Skip comments
        if (line.length() == 0 || line.substr(0, 1) == "#" || line.substr(0, 1) == "%") {
            std::getline(dbFile, line);
            continue;
        }

        string vertexOne;
        string vertexTwo;

        std::istringstream stream(line);
        std::getline(stream, vertexOne, splitter);
        stream >> vertexTwo;

        try {
            firstVertex = std::stoi(vertexOne);
            secondVertex = std::stoi(vertexTwo);
        } catch (const std::exception& e) {
            std::getline(dbFile, line);
            continue;
        }

        if (!zeroflag) {
            if (firstVertex == 0 || secondVertex == 0) {
                zeroflag = true;
                partitioner_logger.log("Graph has zero vertex", "info");
            }
        }

        // Build adjacency list
        std::vector<int> firstEdgeSet = graphStorageMap[firstVertex];
        std::vector<int> vertexEdgeSet = graphEdgeMap[firstVertex];

        if (firstEdgeSet.empty()) {
            vertexCount++;
            edgeCount++;
            firstEdgeSet.push_back(secondVertex);
            vertexEdgeSet.push_back(secondVertex);
        } else {
            if (std::find(firstEdgeSet.begin(), firstEdgeSet.end(), secondVertex) == firstEdgeSet.end()) {
                firstEdgeSet.push_back(secondVertex);
            }
            vertexEdgeSet.push_back(secondVertex);
            edgeCount++;
        }

        graphStorageMap[firstVertex] = firstEdgeSet;
        graphEdgeMap[firstVertex] = vertexEdgeSet;

        std::vector<int> secondEdgeSet = graphStorageMap[secondVertex];

        if (secondEdgeSet.empty()) {
            vertexCount++;
            secondEdgeSet.push_back(firstVertex);
        } else {
            if (std::find(secondEdgeSet.begin(), secondEdgeSet.end(), firstVertex) == secondEdgeSet.end()) {
                secondEdgeSet.push_back(firstVertex);
            }
        }

        graphStorageMap[secondVertex] = secondEdgeSet;

        if (firstVertex > largestVertex) {
            largestVertex = firstVertex;
        }
        if (secondVertex > largestVertex) {
            largestVertex = secondVertex;
        }
        if (firstVertex < smallestVertex) {
            smallestVertex = firstVertex;
        }
        if (secondVertex < smallestVertex) {
            smallestVertex = secondVertex;
        }

        std::getline(dbFile, line);
        while (!line.empty() && line.find_first_not_of(splitter) == std::string::npos) {
            std::getline(dbFile, line);
        }
    }

    dbFile.close();
    partitioner_logger.log("Dataset loaded. Vertices: " + std::to_string(vertexCount) + 
                          ", Edges: " + std::to_string(edgeCount), "info");
}

void EdgeOrderPartitioner::orderEdges() {
    partitioner_logger.log("Ordering edges using greedy algorithm", "info");
    
    orderedEdges.clear();
    std::unordered_map<int, int> remaining_degree;
    std::unordered_map<int, size_t> last_order;
    std::unordered_set<int> remaining_vertices;
    std::unordered_set<int> ordered_vertices;

    // Initialize degrees
    for (const auto& pair : graphStorageMap) {
        int v = pair.first;
        remaining_degree[v] = graphStorageMap[v].size();
        last_order[v] = 0;
        remaining_vertices.insert(v);
    }

    // Compute priority parameters
    size_t num_edges = edgeCount / 2;  // Undirected edges
    double alpha = 0.0;
    double beta = static_cast<double>(nParts);
    
    for (int k = 1; k <= nParts; ++k) {
        alpha += std::floor(static_cast<double>(num_edges) / k);
    }

    // Priority queue comparator
    auto comparator = [&](int a, int b) {
        double pa = alpha * remaining_degree[a] - beta * last_order[a];
        double pb = alpha * remaining_degree[b] - beta * last_order[b];
        return pa > pb;  // Min-heap
    };

    std::priority_queue<int, std::vector<int>, decltype(comparator)> pq(comparator);
    
    // Hash function for edge pairs
    struct PairHash {
        size_t operator()(const std::pair<int, int>& p) const {
            return std::hash<int>()(p.first) ^ (std::hash<int>()(p.second) << 1);
        }
    };
    
    std::unordered_set<std::pair<int, int>, PairHash> ordered_edge_set;

    size_t current_order = 0;
    size_t delta = num_edges / nParts;  // Two-hop threshold

    // Start with first vertex
    if (!remaining_vertices.empty()) {
        int v_min = *remaining_vertices.begin();
        ordered_vertices.insert(v_min);
        remaining_vertices.erase(v_min);

        // Order one-hop neighbors
        for (int u : graphStorageMap[v_min]) {
            int first = std::min(v_min, u);
            int second = std::max(v_min, u);
            std::pair<int, int> edge = {first, second};
            
            if (ordered_edge_set.find(edge) == ordered_edge_set.end()) {
                orderedEdges.push_back(edge);
                ordered_edge_set.insert(edge);
                last_order[v_min] = current_order;
                last_order[u] = current_order;
                current_order++;
                remaining_degree[v_min]--;
                remaining_degree[u]--;
            }
        }

        // Add neighbors to priority queue
        for (int u : graphStorageMap[v_min]) {
            if (remaining_vertices.count(u)) {
                pq.push(u);
            }
        }
    }

    // Greedy expansion
    while (!remaining_vertices.empty() && !pq.empty()) {
        int v_min = pq.top();
        pq.pop();

        if (ordered_vertices.count(v_min) || remaining_degree[v_min] == 0) {
            continue;
        }

        ordered_vertices.insert(v_min);
        remaining_vertices.erase(v_min);

        // Order one-hop neighbors
        for (int u : graphStorageMap[v_min]) {
            int first = std::min(v_min, u);
            int second = std::max(v_min, u);
            std::pair<int, int> edge = {first, second};
            
            if (ordered_edge_set.find(edge) == ordered_edge_set.end() && remaining_degree[v_min] > 0) {
                orderedEdges.push_back(edge);
                ordered_edge_set.insert(edge);
                last_order[v_min] = current_order;
                last_order[u] = current_order;
                current_order++;
                remaining_degree[v_min]--;
                remaining_degree[u]--;
            }
        }

        // Order two-hop neighbors within delta
        for (int u : graphStorageMap[v_min]) {
            if (remaining_degree[u] == 0) continue;
            
            bool within_delta = (current_order - last_order[u]) <= delta;
            if (within_delta) {
                for (int w : graphStorageMap[u]) {
                    if (w == v_min) continue;
                    
                    int first = std::min(u, w);
                    int second = std::max(u, w);
                    std::pair<int, int> edge = {first, second};
                    
                    if (ordered_edge_set.find(edge) == ordered_edge_set.end() && remaining_degree[u] > 0) {
                        orderedEdges.push_back(edge);
                        ordered_edge_set.insert(edge);
                        last_order[u] = current_order;
                        last_order[w] = current_order;
                        current_order++;
                        remaining_degree[u]--;
                        remaining_degree[w]--;
                    }
                }
            }
        }

        // Update priority queue
        for (int u : graphStorageMap[v_min]) {
            if (remaining_vertices.count(u) && remaining_degree[u] > 0) {
                pq.push(u);
            }
        }
    }

    // Add any remaining edges (disconnected components)
    for (const auto& pair : graphStorageMap) {
        int v = pair.first;
        if (remaining_degree[v] > 0) {
            for (int u : graphStorageMap[v]) {
                int first = std::min(v, u);
                int second = std::max(v, u);
                std::pair<int, int> edge = {first, second};
                
                if (ordered_edge_set.find(edge) == ordered_edge_set.end()) {
                    orderedEdges.push_back(edge);
                    ordered_edge_set.insert(edge);
                }
            }
        }
    }

    partitioner_logger.log("Edge ordering completed. Total ordered edges: " + 
                          std::to_string(orderedEdges.size()), "info");
}

std::map<int, int> EdgeOrderPartitioner::chunkEdgesToPartitions() {
    partitioner_logger.log("Chunking ordered edges into " + std::to_string(nParts) + " partitions", "info");
    
    std::map<int, int> partMap;  // vertex -> partition mapping
    size_t edges_per_partition = orderedEdges.size() / nParts;
    size_t remainder = orderedEdges.size() % nParts;

    size_t current_edge = 0;
    for (int part = 0; part < nParts; ++part) {
        size_t chunk_size = edges_per_partition + (part < remainder ? 1 : 0);
        
        for (size_t i = 0; i < chunk_size && current_edge < orderedEdges.size(); ++i, ++current_edge) {
            auto edge = orderedEdges[current_edge];
            int v1 = edge.first;
            int v2 = edge.second;
            
            // Assign vertices to this partition if not already assigned
            if (partMap.find(v1) == partMap.end()) {
                partMap[v1] = part;
            }
            if (partMap.find(v2) == partMap.end()) {
                partMap[v2] = part;
            }
        }
    }

    // Assign any remaining unassigned vertices
    for (const auto& pair : graphStorageMap) {
        int v = pair.first;
        if (partMap.find(v) == partMap.end()) {
            partMap[v] = nParts - 1;  // Assign to last partition
        }
    }

    partitioner_logger.log("Edge chunking completed", "info");
    return partMap;
}

std::vector<std::map<int, std::string>> EdgeOrderPartitioner::partition(int workerCount) {
    partitioner_logger.log("Starting edge-order partitioning with " + std::to_string(workerCount) + " workers", "info");
    
    this->nParts = workerCount;
    
    // Step 1: Order edges
    orderEdges();
    
    // Step 2: Chunk edges into partitions
    std::map<int, int> partMap = chunkEdgesToPartitions();
    
    // Step 3: Create partition files
    createPartitionFiles(partMap);
    
    // Step 4: Update database
    std::time_t time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    string uploadEndTime = ctime(&time);
    string sqlStatement = "UPDATE graph SET vertexcount = '" + std::to_string(this->vertexCount) +
                         "' ,centralpartitioncount = '" + std::to_string(this->nParts) + 
                         "' ,edgecount = '" + std::to_string(this->edgeCount) + 
                         "' WHERE idgraph = '" + std::to_string(this->graphID) + "'";
    this->sqlite->runUpdate(sqlStatement);
    
    this->fullFileList.push_back(this->partitionFileMap);
    this->fullFileList.push_back(this->centralStoreFileList);
    this->fullFileList.push_back(this->centralStoreDuplicateFileList);
    this->fullFileList.push_back(this->partitionAttributeFileList);
    this->fullFileList.push_back(this->centralStoreAttributeFileList);
    this->fullFileList.push_back(this->compositeCentralStoreFileList);
    
    partitioner_logger.log("Partitioning completed successfully", "info");
    return this->fullFileList;
}

std::string EdgeOrderPartitioner::reformatDataSet(string inputFilePath, int graphID) {
    partitioner_logger.log("Reformatting dataset", "info");
    
    // Create mapping for sequential IDs
    int newID = zeroflag ? 0 : 1;
    for (const auto& pair : graphStorageMap) {
        int originalVertex = pair.first;
        if (vertexToIDMap.find(originalVertex) == vertexToIDMap.end()) {
            vertexToIDMap[originalVertex] = newID;
            idToVertexMap[newID] = originalVertex;
            newID++;
        }
    }

    // Write reformatted file
    string reformattedFilePath = Utils::getHomeDir() + "/.jasminegraph/tmp/" + 
                                std::to_string(graphID) + "_reformatted";
    std::ofstream outputFile(reformattedFilePath);
    
    std::ifstream inputFile(inputFilePath);
    string line;
    char splitter = ' ';
    
    std::getline(inputFile, line);
    if (!line.empty()) {
        if (line.find('\t') != std::string::npos) {
            splitter = '\t';
        } else if (line.find(',') != std::string::npos) {
            splitter = ',';
        }
    }

    while (!line.empty()) {
        if (line.length() == 0 || line.substr(0, 1) == "#" || line.substr(0, 1) == "%") {
            std::getline(inputFile, line);
            continue;
        }

        string vertexOne, vertexTwo;
        std::istringstream stream(line);
        std::getline(stream, vertexOne, splitter);
        stream >> vertexTwo;

        try {
            int v1 = std::stoi(vertexOne);
            int v2 = std::stoi(vertexTwo);
            
            outputFile << vertexToIDMap[v1] << " " << vertexToIDMap[v2] << std::endl;
        } catch (const std::exception& e) {
            // Skip invalid lines
        }

        std::getline(inputFile, line);
    }

    inputFile.close();
    outputFile.close();

    partitioner_logger.log("Dataset reformatted successfully", "info");
    return reformattedFilePath;
}

void EdgeOrderPartitioner::loadContentData(string inputAttributeFilePath, 
                                           string graphAttributeType, 
                                           int graphID, 
                                           string attrType) {
    partitioner_logger.log("Loading content data", "info");
    this->graphAttributeType = graphAttributeType;
    
    if (graphAttributeType == Conts::GRAPH_WITH_TEXT_ATTRIBUTES) {
        std::ifstream attributeFile(inputAttributeFilePath);
        string line;
        
        while (std::getline(attributeFile, line)) {
            if (line.empty()) continue;
            
            size_t pos = line.find(' ');
            if (pos != string::npos) {
                int vertexID = std::stoi(line.substr(0, pos));
                string attribute = line.substr(pos + 1);
                attributeDataMap[vertexID] = attribute;
            }
        }
        
        attributeFile.close();
    } else if (graphAttributeType == Conts::GRAPH_WITH_JSON_ATTRIBUTES ||
               graphAttributeType == Conts::GRAPH_WITH_XML_ATTRIBUTES) {
        // TODO: Implement JSON and XML attribute loading if needed
        partitioner_logger.log("JSON/XML attributes not yet implemented", "warn");
    }
    
    partitioner_logger.log("Content data loaded", "info");
}

void EdgeOrderPartitioner::createPartitionFiles(std::map<int, int> partMap) {
    partitioner_logger.log("Creating partition files", "info");
    
    // Initialize partition vertex counts
    for (int i = smallestVertex; i <= largestVertex; i++) {
        if (partMap.find(i) != partMap.end()) {
            partVertexCounts[partMap[i]]++;
        }
    }

    // Populate partition maps
    partitioner_logger.log("Populating edge lists before writing to files", "info");
    for (int part = 0; part < nParts; part++) {
        populatePartMaps(partMap, part);
    }

    // Populate duplicate master graph storage map (for cross-partition edges)
    for (int part = 0; part < nParts; part++) {
        std::map<int, std::map<int, std::vector<int>>> commonCentralStoreEdgePartMap = commonCentralStoreEdgeMap[part];
        
        for (int subPart = 0; subPart < nParts; subPart++) {
            if (part == subPart) {
                continue;
            }
            
            std::map<int, std::vector<int>> partMasterEdgesSet = duplicateMasterGraphStorageMap[subPart];
            std::map<int, std::vector<int>> commonMasterEdgeSet = commonCentralStoreEdgePartMap[subPart];
            
            for (auto& entry : commonMasterEdgeSet) {
                std::vector<int>& centralGraphVertexVector = partMasterEdgesSet[entry.first];
                for (int endVertex : entry.second) {
                    centralGraphVertexVector.push_back(endVertex);
                    masterEdgeCountsWithDups[subPart]++;
                }
                partMasterEdgesSet[entry.first] = centralGraphVertexVector;
            }
            duplicateMasterGraphStorageMap[subPart] = partMasterEdgesSet;
        }
    }

    partitioner_logger.log("Populating edge lists completed", "info");
    partitioner_logger.log("Writing edge lists to files", "info");

    // Calculate thread count
    int threadCount = nParts * 3;
    if (graphAttributeType == Conts::GRAPH_WITH_TEXT_ATTRIBUTES || graphType == Conts::GRAPH_TYPE_RDF) {
        threadCount = nParts * 5;
    }

    std::vector<std::thread> threads;
    for (int part = 0; part < nParts; part++) {
        threads.push_back(std::thread(&EdgeOrderPartitioner::writeSerializedPartitionFiles, this, part));
        threads.push_back(std::thread(&EdgeOrderPartitioner::writeSerializedMasterFiles, this, part));
        threads.push_back(std::thread(&EdgeOrderPartitioner::writeSerializedDuplicateMasterFiles, this, part));
        
        if (graphAttributeType == Conts::GRAPH_WITH_TEXT_ATTRIBUTES) {
            threads.push_back(std::thread(&EdgeOrderPartitioner::writeTextAttributeFilesForPartitions, this, part));
            threads.push_back(std::thread(&EdgeOrderPartitioner::writeTextAttributeFilesForMasterParts, this, part));
        }
        if (graphType == Conts::GRAPH_TYPE_RDF) {
            threads.push_back(std::thread(&EdgeOrderPartitioner::writeRDFAttributeFilesForPartitions, this, part));
            threads.push_back(std::thread(&EdgeOrderPartitioner::writeRDFAttributeFilesForMasterParts, this, part));
        }
    }

    for (auto& thread : threads) {
        thread.join();
    }

    partitioner_logger.log("Writing to files completed", "info");

    // Update partition metadata in database
    for (int part = 0; part < nParts; part++) {
        int masterEdgeCount = masterEdgeCounts[part];
        int masterEdgeCountWithDups = masterEdgeCountsWithDups[part];

        string sqlStatement = "UPDATE partition SET central_edgecount = '" + std::to_string(masterEdgeCount) +
                             "', central_edgecount_with_dups = '" + std::to_string(masterEdgeCountWithDups) +
                             "' WHERE graph_idgraph = '" + std::to_string(this->graphID) + 
                             "' AND idpartition = '" + std::to_string(part) + "'";
        dbLock.lock();
        this->sqlite->runUpdate(sqlStatement);
        dbLock.unlock();
    }
}

void EdgeOrderPartitioner::populatePartMaps(std::map<int, int> partMap, int part) {
    int partitionEdgeCount = 0;
    std::map<int, std::vector<int>> partEdgesSet;
    std::map<int, std::vector<int>> partMasterEdgesSet;
    std::map<int, std::map<int, std::vector<int>>> commonMasterEdgeSet;
    std::unordered_set<int> centralPartVertices;

    if (graphType == Conts::GRAPH_TYPE_NORMAL_REFORMATTED) {
        // Handle reformatted graphs (with mapped IDs)
        for (auto& entry : graphEdgeMap) {
            int startVertexID = entry.first;
            int startVertexPart = partMap[startVertexID];
            int startVertexActual = idToVertexMap[startVertexID];
            
            if (startVertexPart == part) {
                std::vector<int> localGraphVertexVector;
                std::vector<int> centralGraphVertexVector;

                for (int endVertexID : entry.second) {
                    int endVertexPart = partMap[endVertexID];
                    int endVertexActual = idToVertexMap[endVertexID];

                    if (endVertexPart == part) {
                        partitionEdgeCount++;
                        localGraphVertexVector.push_back(endVertexActual);
                    } else {
                        centralGraphVertexVector.push_back(endVertexActual);
                        masterEdgeCounts[part]++;
                        masterEdgeCountsWithDups[part]++;
                        centralPartVertices.insert(endVertexActual);
                        commonMasterEdgeSet[endVertexPart][startVertexActual].push_back(endVertexActual);
                    }
                }

                if (!localGraphVertexVector.empty()) {
                    partEdgesSet[startVertexActual] = localGraphVertexVector;
                }
                if (!centralGraphVertexVector.empty()) {
                    partMasterEdgesSet[startVertexActual] = centralGraphVertexVector;
                }
            }
        }
    } else {
        // Handle normal graphs
        for (auto& entry : graphEdgeMap) {
            int startVertex = entry.first;
            int startVertexPart = partMap[startVertex];
            
            if (startVertexPart == part) {
                std::vector<int> localGraphVertexVector;
                std::vector<int> centralGraphVertexVector;

                for (int endVertex : entry.second) {
                    int endVertexPart = partMap[endVertex];

                    if (endVertexPart == part) {
                        partitionEdgeCount++;
                        localGraphVertexVector.push_back(endVertex);
                    } else {
                        masterEdgeCounts[part]++;
                        masterEdgeCountsWithDups[part]++;
                        centralPartVertices.insert(endVertex);
                        centralGraphVertexVector.push_back(endVertex);
                        commonMasterEdgeSet[endVertexPart][startVertex].push_back(endVertex);
                    }
                }

                if (!localGraphVertexVector.empty()) {
                    partEdgesSet[startVertex] = localGraphVertexVector;
                }
                if (!centralGraphVertexVector.empty()) {
                    partMasterEdgesSet[startVertex] = centralGraphVertexVector;
                }
            }
        }
    }

    partitionedLocalGraphStorageMap[part] = partEdgesSet;
    masterGraphStorageMap[part] = partMasterEdgesSet;
    commonCentralStoreEdgeMap[part] = commonMasterEdgeSet;

    string sqlStatement =
        "INSERT INTO partition (idpartition,graph_idgraph,vertexcount,central_vertexcount,edgecount) VALUES(\"" +
        std::to_string(part) + "\", \"" + std::to_string(this->graphID) + "\", \"" +
        std::to_string(partVertexCounts[part]) + "\",\"" + std::to_string(centralPartVertices.size()) + "\",\"" +
        std::to_string(partitionEdgeCount) + "\")";
    dbLock.lock();
    this->sqlite->runUpdate(sqlStatement);
    dbLock.unlock();
}

void EdgeOrderPartitioner::writeSerializedPartitionFiles(int part) {
    string outputFilePart = outputFilePath + "/" + std::to_string(this->graphID) + "_" + std::to_string(part);
    std::map<int, std::vector<int>> partEdgeMap = partitionedLocalGraphStorageMap[part];

    JasmineGraphHashMapLocalStore::storePartEdgeMap(partEdgeMap, outputFilePart);
    Utils::compressFile(outputFilePart);
    
    partFileMutex.lock();
    partitionFileMap[part] = outputFilePart + ".gz";
    partFileMutex.unlock();
    
    partitioner_logger.log("Serializing done for local part " + std::to_string(part), "info");
}

void EdgeOrderPartitioner::writeSerializedMasterFiles(int part) {
    string outputFilePartMaster =
        outputFilePath + "/" + std::to_string(this->graphID) + "_centralstore_" + std::to_string(part);
    std::map<int, std::vector<int>> partMasterEdgeMap = masterGraphStorageMap[part];

    JasmineGraphHashMapCentralStore::storePartEdgeMap(partMasterEdgeMap, outputFilePartMaster);
    Utils::compressFile(outputFilePartMaster);
    
    masterFileMutex.lock();
    centralStoreFileList[part] = outputFilePartMaster + ".gz";
    masterFileMutex.unlock();
    
    partitioner_logger.log("Serializing done for central part " + std::to_string(part), "info");
}

void EdgeOrderPartitioner::writeSerializedDuplicateMasterFiles(int part) {
    string outputFilePartMaster =
        outputFilePath + "/" + std::to_string(this->graphID) + "_centralstore_dp_" + std::to_string(part);
    std::map<int, std::vector<int>> partMasterEdgeMap = duplicateMasterGraphStorageMap[part];

    JasmineGraphHashMapCentralStore::storePartEdgeMap(partMasterEdgeMap, outputFilePartMaster);
    Utils::compressFile(outputFilePartMaster);
    
    masterFileMutex.lock();
    centralStoreDuplicateFileList[part] = outputFilePartMaster + ".gz";
    masterFileMutex.unlock();
    
    partitioner_logger.log("Serializing done for duplicate central part " + std::to_string(part), "info");
}

void EdgeOrderPartitioner::writeSerializedCompositeMasterFiles(std::string part) {
    // Composite central store implementation (optional, similar to MetisPartitioner)
    string outputFilePartMaster =
        outputFilePath + "/" + std::to_string(this->graphID) + "_centralstore_composite_" + part;
    std::map<int, std::vector<int>> partMasterEdgeMap = compositeMasterGraphStorageMap[part];

    JasmineGraphHashMapCentralStore::storePartEdgeMap(partMasterEdgeMap, outputFilePartMaster);
    Utils::compressFile(outputFilePartMaster);
    
    masterFileMutex.lock();
    compositeCentralStoreFileList[std::stoi(part)] = outputFilePartMaster + ".gz";
    masterFileMutex.unlock();
}

void EdgeOrderPartitioner::writeTextAttributeFilesForPartitions(int part) {
    string attributeFilePart =
        outputFilePath + "/" + std::to_string(this->graphID) + "_attributes_" + std::to_string(part);
    std::map<int, std::vector<int>> partEdgeMap = partitionedLocalGraphStorageMap[part];

    std::ofstream partfile(attributeFilePart);
    std::unordered_set<int> partVertices;

    for (auto& entry : partEdgeMap) {
        int vertex1 = entry.first;
        if (partVertices.insert(vertex1).second) {
            auto vertex1_ele = attributeDataMap.find(vertex1);
            if (vertex1_ele != attributeDataMap.end()) {
                partfile << vertex1_ele->first << "\t" << vertex1_ele->second << std::endl;
            }
        }

        for (int vertex2 : entry.second) {
            if (partVertices.insert(vertex2).second) {
                auto vertex2_ele = attributeDataMap.find(vertex2);
                if (vertex2_ele != attributeDataMap.end()) {
                    partfile << vertex2_ele->first << "\t" << vertex2_ele->second << std::endl;
                }
            }
        }
    }

    partfile.close();
    Utils::compressFile(attributeFilePart);
    
    partAttrFileMutex.lock();
    partitionAttributeFileList[part] = attributeFilePart + ".gz";
    partAttrFileMutex.unlock();
    
    partitioner_logger.log("Attribute writing done for local part " + std::to_string(part), "info");
}

void EdgeOrderPartitioner::writeTextAttributeFilesForMasterParts(int part) {
    string attributeFilePartMaster =
        outputFilePath + "/" + std::to_string(this->graphID) + "_centralstore_attributes_" + std::to_string(part);
    std::map<int, std::vector<int>> partMasterEdgeMap = masterGraphStorageMap[part];

    std::ofstream partfile(attributeFilePartMaster);
    std::unordered_set<int> masterPartVertices;

    for (auto& entry : partMasterEdgeMap) {
        int vertex1 = entry.first;
        if (masterPartVertices.insert(vertex1).second) {
            auto vertex1_ele = attributeDataMap.find(vertex1);
            if (vertex1_ele != attributeDataMap.end()) {
                partfile << vertex1_ele->first << "\t" << vertex1_ele->second << std::endl;
            }
        }

        for (int vertex2 : entry.second) {
            if (masterPartVertices.insert(vertex2).second) {
                auto vertex2_ele = attributeDataMap.find(vertex2);
                if (vertex2_ele != attributeDataMap.end()) {
                    partfile << vertex2_ele->first << "\t" << vertex2_ele->second << std::endl;
                }
            }
        }
    }

    partfile.close();
    Utils::compressFile(attributeFilePartMaster);
    
    masterAttrFileMutex.lock();
    centralStoreAttributeFileList[part] = attributeFilePartMaster + ".gz";
    masterAttrFileMutex.unlock();
    
    partitioner_logger.log("Attribute writing done for central part " + std::to_string(part), "info");
}

void EdgeOrderPartitioner::writeRDFAttributeFilesForPartitions(int part) {
    std::map<int, std::vector<int>> partEdgeMap = partitionedLocalGraphStorageMap[part];
    std::map<long, std::vector<string>> partitionedEdgeAttributes;

    string attributeFilePart =
        outputFilePath + "/" + std::to_string(this->graphID) + "_attributes_" + std::to_string(part);

    for (auto& entry : partEdgeMap) {
        for (int vertex2 : entry.second) {
            auto edgeEntry = edgeMap.find(std::make_pair(entry.first, vertex2));
            if (edgeEntry != edgeMap.end()) {
                long article_id = edgeEntry->second;
                std::vector<string> attributes;
                auto arrayIt = articlesMap.find(article_id);
                if (arrayIt != articlesMap.end()) {
                    for (int i = 0; i < 7; i++) {
                        attributes.push_back(arrayIt->second[i]);
                    }
                    partitionedEdgeAttributes[article_id] = attributes;
                }
            }
        }
    }

    JasmineGraphHashMapLocalStore::storeAttributes(partitionedEdgeAttributes, attributeFilePart);
    Utils::compressFile(attributeFilePart);
    
    partAttrFileMutex.lock();
    partitionAttributeFileList[part] = attributeFilePart + ".gz";
    partAttrFileMutex.unlock();
}

void EdgeOrderPartitioner::writeRDFAttributeFilesForMasterParts(int part) {
    std::map<int, std::vector<int>> partMasterEdgeMap = masterGraphStorageMap[part];
    std::map<long, std::vector<string>> centralStoreEdgeAttributes;

    string attributeFilePartMaster =
        outputFilePath + "/" + std::to_string(this->graphID) + "_centralstore_attributes_" + std::to_string(part);

    for (auto& entry : partMasterEdgeMap) {
        for (int vertex2 : entry.second) {
            auto edgeEntry = edgeMap.find(std::make_pair(entry.first, vertex2));
            if (edgeEntry != edgeMap.end()) {
                long article_id = edgeEntry->second;
                std::vector<string> attributes;
                auto arrayIt = articlesMap.find(article_id);
                if (arrayIt != articlesMap.end()) {
                    for (int i = 0; i < 7; i++) {
                        attributes.push_back(arrayIt->second[i]);
                    }
                    centralStoreEdgeAttributes[article_id] = attributes;
                }
            }
        }
    }

    JasmineGraphHashMapLocalStore::storeAttributes(centralStoreEdgeAttributes, attributeFilePartMaster);
    Utils::compressFile(attributeFilePartMaster);
    
    masterAttrFileMutex.lock();
    centralStoreAttributeFileList[part] = attributeFilePartMaster + ".gz";
    masterAttrFileMutex.unlock();
}
