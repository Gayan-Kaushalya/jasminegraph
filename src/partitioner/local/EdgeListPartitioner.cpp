/**
Copyright 2019 JasmineGraph Team
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

#include "EdgeListPartitioner.h"

#include <flatbuffers/flatbuffers.h>

#include <iterator>

#include "../../util/Conts.h"
#include "../../util/logger/Logger.h"
#include "RDFParser.h"

Logger edgelist_partitioner_logger;
std::mutex edgelist_partFileMutex;
std::mutex edgelist_masterFileMutex;
std::mutex edgelist_partAttrFileMutex;
std::mutex edgelist_masterAttrFileMutex;
std::mutex edgelist_dbLock;

EdgeListPartitioner::EdgeListPartitioner(SQLiteDBInterface *sqlite) {
    this->sqlite = sqlite;
    std::string partitionCount = Utils::getJasmineGraphProperty("org.jasminegraph.server.npartitions");
    nParts = atoi(partitionCount.c_str());
}

void EdgeListPartitioner::loadDataSet(string inputFilePath, int graphID) {
    edgelist_partitioner_logger.log("Processing dataset for edge list partitioning", "info");
    this->graphID = graphID;
    
    // Output directory is created under the users home directory '~/.jasminegraph/tmp/'
    this->outputFilePath = Utils::getHomeDir() + "/.jasminegraph/tmp/" + std::to_string(this->graphID);

    Utils::createDirectory(Utils::getHomeDir() + "/.jasminegraph/tmp");
    Utils::createDirectory(this->outputFilePath);

    std::ifstream dbFile;
    dbFile.open(inputFilePath, std::ios::binary | std::ios::in);

    int firstVertex = -1;
    int secondVertex = -1;
    string line;
    char splitter;

    std::getline(dbFile, line);

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
        string vertexOne;
        string vertexTwo;

        std::istringstream stream(line);
        std::getline(stream, vertexOne, splitter);
        stream >> vertexTwo;

        firstVertex = std::stoi(vertexOne);
        secondVertex = std::stoi(vertexTwo);

        if (!zeroflag) {
            if (firstVertex == 0 || secondVertex == 0) {
                zeroflag = true;
                edgelist_partitioner_logger.log("Graph has zero vertex", "info");
            }
        }

        // Add edge to the edge list
        edgeList.push_back(std::make_pair(firstVertex, secondVertex));
        edgeCount++;

        // Track unique vertices
        if (vertexEdges[firstVertex].empty()) {
            vertexCount++;
        }
        vertexEdges[firstVertex].insert(secondVertex);

        if (vertexEdges[secondVertex].empty()) {
            vertexCount++;
        }
        vertexEdges[secondVertex].insert(firstVertex);

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
    
    edgelist_partitioner_logger.log("Dataset loaded. Total edges: " + std::to_string(edgeCount) + 
                                     ", Total vertices: " + std::to_string(vertexCount), "info");
}

std::vector<std::map<int, std::string>> EdgeListPartitioner::partitionByEdgeList(string partitionCount) {
    edgelist_partitioner_logger.log("Starting edge list partitioning", "info");
    
    if (partitionCount != "") {
        nParts = atoi(partitionCount.c_str());
    } else {
        edgelist_partitioner_logger.log("Using the default partition count: " + std::to_string(nParts), "info");
    }

    if (edgeList.empty()) {
        edgelist_partitioner_logger.log("No edges to partition", "error");
        return std::vector<std::map<int, std::string>>{};
    }

    // Step 1: Sort edges by source vertex for better locality
    edgelist_partitioner_logger.log("Sorting edges by source vertex", "info");
    std::sort(edgeList.begin(), edgeList.end(), 
              [](const std::pair<int, int>& a, const std::pair<int, int>& b) {
                  return a.first < b.first || (a.first == b.first && a.second < b.second);
              });

    // Step 2: Chunk edges into partitions
    edgelist_partitioner_logger.log("Chunking edges into " + std::to_string(nParts) + " partitions", "info");
    
    long edgesPerPartition = edgeCount / nParts;
    long remainingEdges = edgeCount % nParts;
    
    std::map<int, int> partMap;  // Maps vertex ID to partition ID
    std::unordered_set<int> allVertices;
    
    // Collect all unique vertices
    for (const auto& edge : edgeList) {
        allVertices.insert(edge.first);
        allVertices.insert(edge.second);
    }

    // Step 3: Assign edges to partitions in chunks
    long currentEdgeIndex = 0;
    std::map<int, std::vector<std::pair<int, int>>> partitionEdges;
    
    for (int part = 0; part < nParts; part++) {
        long edgesForThisPart = edgesPerPartition;
        if (part < remainingEdges) {
            edgesForThisPart++;  // Distribute remaining edges
        }
        
        long endIndex = std::min(currentEdgeIndex + edgesForThisPart, (long)edgeList.size());
        
        for (long i = currentEdgeIndex; i < endIndex; i++) {
            partitionEdges[part].push_back(edgeList[i]);
        }
        
        currentEdgeIndex = endIndex;
    }

    // Step 4: Assign primary partition for each vertex based on where it appears most
    std::map<int, std::map<int, int>> vertexPartitionCounts;  // vertex -> partition -> count
    
    for (int part = 0; part < nParts; part++) {
        for (const auto& edge : partitionEdges[part]) {
            vertexPartitionCounts[edge.first][part]++;
            vertexPartitionCounts[edge.second][part]++;
        }
    }

    // Assign each vertex to the partition where it appears most frequently
    for (int vertex : allVertices) {
        int maxCount = 0;
        int bestPartition = 0;
        
        for (const auto& partCount : vertexPartitionCounts[vertex]) {
            if (partCount.second > maxCount) {
                maxCount = partCount.second;
                bestPartition = partCount.first;
            }
        }
        
        partMap[vertex] = bestPartition;
    }

    edgelist_partitioner_logger.log("Vertex assignment completed", "info");

    // Step 5: Create partition files
    createPartitionFiles(partMap);

    // Step 6: Update database
    string sqlStatement = "UPDATE graph SET vertexcount = '" + std::to_string(this->vertexCount) +
                          "' ,centralpartitioncount = '" + std::to_string(this->nParts) + "' ,edgecount = '" +
                          std::to_string(this->edgeCount) + "' WHERE idgraph = '" +
                          std::to_string(this->graphID) + "'";
    this->sqlite->runUpdate(sqlStatement);

    this->fullFileList.push_back(this->partitionFileMap);
    this->fullFileList.push_back(this->centralStoreFileList);
    this->fullFileList.push_back(this->centralStoreDuplicateFileList);
    this->fullFileList.push_back(this->partitionAttributeFileList);
    this->fullFileList.push_back(this->centralStoreAttributeFileList);
    this->fullFileList.push_back(this->compositeCentralStoreFileList);

    edgelist_partitioner_logger.log("###EDGE_LIST_PARTITIONING_COMPLETE###", "info");
    
    return this->fullFileList;
}

void EdgeListPartitioner::createPartitionFiles(std::map<int, int> partMap) {
    std::vector<size_t> centralStoreSizeVector;
    std::vector<int> sortedPartVector;
    
    for (const auto& vertexPair : vertexEdges) {
        partVertexCounts[partMap[vertexPair.first]]++;
    }
    
    edgelist_partitioner_logger.log("Populating edge lists before writing to files", "info");
    edgeMap = GetConfig::getEdgeMap();
    articlesMap = GetConfig::getAttributesMap();

    // Populate partition maps
    for (int part = 0; part < nParts; part++) {
        populatePartMaps(partMap, part);
    }

    // Populate the masterEdgeLists with the remaining edges
    edgelist_partitioner_logger.log("Populating duplicate master edge lists", "info");
    
    for (const auto& edge : edgeList) {
        int firstVertex = edge.first;
        int secondVertex = edge.second;
        int firstPart = partMap[firstVertex];
        int secondPart = partMap[secondVertex];

        if (firstPart != secondPart) {
            // This edge crosses partitions
            duplicateMasterGraphStorageMap[secondPart][firstVertex].push_back(secondVertex);
            masterEdgeCountsWithDups[secondPart]++;
        }
    }

    edgelist_partitioner_logger.log("Populating edge lists completed", "info");
    edgelist_partitioner_logger.log("Writing edge lists to files", "info");
    
    int threadCount = nParts * 3;
    if (graphAttributeType == Conts::GRAPH_WITH_TEXT_ATTRIBUTES || graphType == Conts::GRAPH_TYPE_RDF) {
        threadCount = nParts * 5;
    }
    
    std::thread threads[threadCount];
    int count = 0;
    
    for (int part = 0; part < nParts; part++) {
        threads[count++] = std::thread(&EdgeListPartitioner::writeSerializedPartitionFiles, this, part);
        threads[count++] = std::thread(&EdgeListPartitioner::writeSerializedMasterFiles, this, part);
        threads[count++] = std::thread(&EdgeListPartitioner::writeSerializedDuplicateMasterFiles, this, part);
        
        if (graphAttributeType == Conts::GRAPH_WITH_TEXT_ATTRIBUTES) {
            threads[count++] = std::thread(&EdgeListPartitioner::writeTextAttributeFilesForPartitions, this, part);
            threads[count++] = std::thread(&EdgeListPartitioner::writeTextAttributeFilesForMasterParts, this, part);
        }
        if (graphType == Conts::GRAPH_TYPE_RDF) {
            threads[count++] = std::thread(&EdgeListPartitioner::writeRDFAttributeFilesForPartitions, this, part);
            threads[count++] = std::thread(&EdgeListPartitioner::writeRDFAttributeFilesForMasterParts, this, part);
        }
    }

    for (int tc = 0; tc < count; tc++) {
        threads[tc].join();
    }
    
    edgelist_partitioner_logger.log("Writing to files completed", "info");

    // Update partition statistics in database
    for (int part = 0; part < nParts; part++) {
        int masterEdgeCount = masterEdgeCounts[part];
        centralStoreSizeVector.push_back(masterEdgeCounts[part]);
        sortedPartVector.push_back(part);
        int masterEdgeCountWithDups = masterEdgeCountsWithDups[part];

        string sqlStatement = "UPDATE partition SET central_edgecount = '" + std::to_string(masterEdgeCount) +
                              "', central_edgecount_with_dups = '" + std::to_string(masterEdgeCountWithDups) +
                              "' WHERE graph_idgraph = '" + std::to_string(this->graphID) + "' AND idpartition = '" +
                              std::to_string(part) + "'";
        edgelist_dbLock.lock();
        this->sqlite->runUpdate(sqlStatement);
        edgelist_dbLock.unlock();
    }

    // Create composite central stores if needed (same logic as MetisPartitioner)
    if (nParts > Conts::COMPOSITE_CENTRAL_STORE_WORKER_THRESHOLD) {
        edgelist_partitioner_logger.log("Creating composite central stores", "info");
        
        // Sort partitions by central store size
        bool haveSwapped = true;
        for (unsigned j = 1; haveSwapped && j < centralStoreSizeVector.size(); ++j) {
            haveSwapped = false;
            for (unsigned i = 0; i < centralStoreSizeVector.size() - j; ++i) {
                if (centralStoreSizeVector[i] < centralStoreSizeVector[i + 1]) {
                    haveSwapped = true;
                    std::swap(centralStoreSizeVector[i], centralStoreSizeVector[i + 1]);
                    std::swap(sortedPartVector[i], sortedPartVector[i + 1]);
                }
            }
        }

        std::map<int, std::vector<size_t>> centralStoreGroups;
        std::map<int, std::vector<int>> partitionGroups;
        std::vector<std::string> compositeGraphIdList;
        int partitionLoop = 0;

        for (size_t centralStoreSize : centralStoreSizeVector) {
            std::vector<size_t> minSumGroup = centralStoreGroups[0];
            std::vector<int> minPartitionGroup = partitionGroups[0];
            size_t minGroupTotal = 0;
            int minGroupIndex = 0;

            for (size_t size : minSumGroup) {
                minGroupTotal += size;
            }

            for (int loop = 0; loop < Conts::NUMBER_OF_COMPOSITE_CENTRAL_STORES; loop++) {
                std::vector<size_t> currentGroup = centralStoreGroups[loop];
                size_t currentGroupTotal = 0;

                for (size_t size : currentGroup) {
                    currentGroupTotal += size;
                }

                if (currentGroupTotal < minGroupTotal) {
                    minSumGroup = currentGroup;
                    minGroupTotal = currentGroupTotal;
                    minPartitionGroup = partitionGroups[loop];
                    minGroupIndex = loop;
                }
            }

            minSumGroup.push_back(centralStoreSize);
            centralStoreGroups[minGroupIndex] = minSumGroup;

            minPartitionGroup.push_back(partitionLoop);
            partitionGroups[minGroupIndex] = minPartitionGroup;

            partitionLoop++;
        }

        for (const auto& [group, partitionList] : partitionGroups) {
            if (partitionList.size() > 0) {
                std::string aggregatePartitionId = "";
                std::map<int, std::vector<int>> tempCompositeMap;

                for (int partitionId : partitionList) {
                    aggregatePartitionId = std::to_string(partitionId) + "_" + aggregatePartitionId;

                    std::map<int, std::vector<int>> currentStorageMap = masterGraphStorageMap[partitionId];

                    for (const auto& [startVertex, secondVertexVector] : currentStorageMap) {
                        std::vector<int>& compositeMapSecondVertexVector = tempCompositeMap[startVertex];

                        for (int secondVertex : secondVertexVector) {
                            if (std::find(compositeMapSecondVertexVector.begin(), 
                                        compositeMapSecondVertexVector.end(),
                                        secondVertex) == compositeMapSecondVertexVector.end()) {
                                compositeMapSecondVertexVector.push_back(secondVertex);
                            }
                        }
                    }
                }

                std::string adjustedAggregatePartitionId =
                    aggregatePartitionId.substr(0, aggregatePartitionId.size() - 1);
                compositeGraphIdList.push_back(adjustedAggregatePartitionId);
                compositeMasterGraphStorageMap[adjustedAggregatePartitionId] = tempCompositeMap;
            }
        }

        std::thread compositeCopyThreads[compositeGraphIdList.size()];
        int compositeCopyCount = 0;

        for (const std::string& compositeGraphId : compositeGraphIdList) {
            compositeCopyThreads[compositeCopyCount++] =
                std::thread(&EdgeListPartitioner::writeSerializedCompositeMasterFiles, this, compositeGraphId);
        }

        for (int tc = 0; tc < compositeCopyCount; tc++) {
            compositeCopyThreads[tc].join();
        }
    }
}

void EdgeListPartitioner::populatePartMaps(std::map<int, int> partMap, int part) {
    int partitionEdgeCount = 0;
    std::map<int, std::vector<int>> partEdgesSet;
    std::map<int, std::vector<int>> partMasterEdgesSet;
    std::unordered_set<int> centralPartVertices;

    // Process all edges
    for (const auto& edge : edgeList) {
        int startVertex = edge.first;
        int endVertex = edge.second;
        int startVertexPart = partMap[startVertex];
        int endVertexPart = partMap[endVertex];

        // If start vertex belongs to this partition
        if (startVertexPart == part) {
            if (endVertexPart == part) {
                // Local edge
                partEdgesSet[startVertex].push_back(endVertex);
                partitionEdgeCount++;
            } else {
                // Cross-partition edge
                partMasterEdgesSet[startVertex].push_back(endVertex);
                masterEdgeCounts[part]++;
                masterEdgeCountsWithDups[part]++;
                centralPartVertices.insert(endVertex);
            }
        }
    }

    partitionedLocalGraphStorageMap[part] = partEdgesSet;
    masterGraphStorageMap[part] = partMasterEdgesSet;

    string sqlStatement =
        "INSERT INTO partition (idpartition,graph_idgraph,vertexcount,central_vertexcount,edgecount) VALUES(\"" +
        std::to_string(part) + "\", \"" + std::to_string(this->graphID) + "\", \"" +
        std::to_string(partVertexCounts[part]) + "\",\"" + std::to_string(centralPartVertices.size()) + "\",\"" +
        std::to_string(partitionEdgeCount) + "\")";
    edgelist_dbLock.lock();
    this->sqlite->runUpdate(sqlStatement);
    edgelist_dbLock.unlock();
}

void EdgeListPartitioner::writeSerializedPartitionFiles(int part) {
    string outputFilePart = outputFilePath + "/" + std::to_string(this->graphID) + "_" + std::to_string(part);

    std::map<int, std::vector<int>> partEdgeMap = partitionedLocalGraphStorageMap[part];

    JasmineGraphHashMapLocalStore::storePartEdgeMap(partEdgeMap, outputFilePart);

    Utils::compressFile(outputFilePart);
    edgelist_partFileMutex.lock();
    partitionFileMap[part] = outputFilePart + ".gz";
    edgelist_partFileMutex.unlock();
    edgelist_partitioner_logger.log("Serializing done for local part " + std::to_string(part), "info");
}

void EdgeListPartitioner::writeSerializedMasterFiles(int part) {
    string outputFilePartMaster =
        outputFilePath + "/" + std::to_string(this->graphID) + "_centralstore_" + std::to_string(part);

    std::map<int, std::vector<int>> partMasterEdgeMap = masterGraphStorageMap[part];

    JasmineGraphHashMapCentralStore::storePartEdgeMap(partMasterEdgeMap, outputFilePartMaster);

    Utils::compressFile(outputFilePartMaster);
    edgelist_masterFileMutex.lock();
    centralStoreFileList[part] = outputFilePartMaster + ".gz";
    edgelist_masterFileMutex.unlock();
    edgelist_partitioner_logger.log("Serializing done for central part " + std::to_string(part), "info");
}

void EdgeListPartitioner::writeSerializedDuplicateMasterFiles(int part) {
    string outputFilePartMaster =
        outputFilePath + "/" + std::to_string(this->graphID) + "_centralstore_dp_" + std::to_string(part);

    std::map<int, std::vector<int>> partMasterEdgeMap = duplicateMasterGraphStorageMap[part];

    JasmineGraphHashMapCentralStore::storePartEdgeMap(partMasterEdgeMap, outputFilePartMaster);

    Utils::compressFile(outputFilePartMaster);
    edgelist_masterFileMutex.lock();
    centralStoreDuplicateFileList[part] = outputFilePartMaster + ".gz";
    edgelist_masterFileMutex.unlock();
    edgelist_partitioner_logger.log("Serializing done for duplicate central part " + std::to_string(part), "info");
}

void EdgeListPartitioner::writeTextAttributeFilesForPartitions(int part) {
    string attributeFilePart =
        outputFilePath + "/" + std::to_string(this->graphID) + "_attributes_" + std::to_string(part);

    std::map<int, std::vector<int>> partEdgeMap = partitionedLocalGraphStorageMap[part];

    std::ofstream partfile;
    partfile.open(attributeFilePart);

    std::unordered_set<int> partVertices;

    for (const auto& [vertex1, neighbors] : partEdgeMap) {
        if (partVertices.insert(vertex1).second) {
            auto vertex1_ele = attributeDataMap.find(vertex1);
            if (vertex1_ele != attributeDataMap.end()) {
                partfile << vertex1_ele->first << "\t" << vertex1_ele->second << std::endl;
            }
        }

        for (int vertex2 : neighbors) {
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
    edgelist_partAttrFileMutex.lock();
    partitionAttributeFileList[part] = attributeFilePart + ".gz";
    edgelist_partAttrFileMutex.unlock();
    edgelist_partitioner_logger.log("Attribute writing done for local part " + std::to_string(part), "info");
}

void EdgeListPartitioner::writeTextAttributeFilesForMasterParts(int part) {
    string attributeFilePartMaster =
        outputFilePath + "/" + std::to_string(this->graphID) + "_centralstore_attributes_" + std::to_string(part);

    std::map<int, std::vector<int>> partMasterEdgeMap = masterGraphStorageMap[part];

    std::ofstream partfile;
    partfile.open(attributeFilePartMaster);
    std::unordered_set<int> masterPartVertices;

    for (const auto& [vertex1, neighbors] : partMasterEdgeMap) {
        if (masterPartVertices.insert(vertex1).second) {
            auto vertex1_ele = attributeDataMap.find(vertex1);
            if (vertex1_ele != attributeDataMap.end()) {
                partfile << vertex1_ele->first << "\t" << vertex1_ele->second << std::endl;
            }
        }

        for (int vertex2 : neighbors) {
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
    edgelist_masterAttrFileMutex.lock();
    centralStoreAttributeFileList[part] = attributeFilePartMaster + ".gz";
    edgelist_masterAttrFileMutex.unlock();
    edgelist_partitioner_logger.log("Attribute writing done for central part " + std::to_string(part), "info");
}

void EdgeListPartitioner::writeRDFAttributeFilesForPartitions(int part) {
    std::map<int, std::vector<int>> partEdgeMap = partitionedLocalGraphStorageMap[part];
    std::map<long, std::vector<string>> partitionedEdgeAttributes;

    string attributeFilePart =
        outputFilePath + "/" + std::to_string(this->graphID) + "_attributes_" + std::to_string(part);

    for (const auto& [vertex1, neighbors] : partEdgeMap) {
        for (int vertex2 : neighbors) {
            auto entry = edgeMap.find(std::make_pair(vertex1, vertex2));
            if (entry != edgeMap.end()) {
                long article_id = entry->second;
                std::vector<string> attributes;
                auto arrayIt = articlesMap.find(article_id);
                if (arrayIt != articlesMap.end()) {
                    auto array = arrayIt->second;
                    for (int itt = 0; itt < 7; itt++) {
                        attributes.push_back(array[itt]);
                    }
                    partitionedEdgeAttributes.insert({article_id, attributes});
                }
            }
        }
    }

    JasmineGraphHashMapLocalStore::storeAttributes(partitionedEdgeAttributes, attributeFilePart);

    Utils::compressFile(attributeFilePart);
    edgelist_partAttrFileMutex.lock();
    partitionAttributeFileList[part] = attributeFilePart + ".gz";
    edgelist_partAttrFileMutex.unlock();
}

void EdgeListPartitioner::writeRDFAttributeFilesForMasterParts(int part) {
    std::map<int, std::vector<int>> partMasterEdgeMap = masterGraphStorageMap[part];
    std::map<long, std::vector<string>> centralStoreEdgeAttributes;

    string attributeFilePartMaster =
        outputFilePath + "/" + std::to_string(this->graphID) + "_centralstore_attributes_" + std::to_string(part);

    for (const auto& [vertex1, neighbors] : partMasterEdgeMap) {
        for (int vertex2 : neighbors) {
            auto entry = edgeMap.find(std::make_pair(vertex1, vertex2));
            if (entry != edgeMap.end()) {
                long article_id = entry->second;
                std::vector<string> attributes;
                auto arrayIt = articlesMap.find(article_id);
                if (arrayIt != articlesMap.end()) {
                    auto array = arrayIt->second;
                    for (int itt = 0; itt < 7; itt++) {
                        attributes.push_back(array[itt]);
                    }
                    centralStoreEdgeAttributes.insert({article_id, attributes});
                }
            }
        }
    }

    JasmineGraphHashMapLocalStore::storeAttributes(centralStoreEdgeAttributes, attributeFilePartMaster);

    Utils::compressFile(attributeFilePartMaster);
    edgelist_masterAttrFileMutex.lock();
    centralStoreAttributeFileList[part] = attributeFilePartMaster + ".gz";
    edgelist_masterAttrFileMutex.unlock();
}

std::string EdgeListPartitioner::reformatDataSet(string inputFilePath, int graphID) {
    this->graphID = graphID;

    std::ifstream inFile;
    inFile.open(inputFilePath, std::ios::binary | std::ios::in);

    string outputFile = Utils::getHomeDir() + "/.jasminegraph/tmp/" + std::to_string(this->graphID) + "/" +
                        std::to_string(this->graphID);
    std::ofstream outFile;
    outFile.open(outputFile);

    int firstVertex = -1;
    int secondVertex = -1;
    string line;
    char splitter;

    std::getline(inFile, line);

    if (!line.empty()) {
        if (line.find(" ") != std::string::npos) {
            splitter = ' ';
        } else if (line.find('\t') != std::string::npos) {
            splitter = '\t';
        } else if (line.find(",") != std::string::npos) {
            splitter = ',';
        }
    }

    int idCounter = 1;

    while (!line.empty()) {
        string vertexOne;
        string vertexTwo;

        std::istringstream stream(line);
        std::getline(stream, vertexOne, splitter);
        stream >> vertexTwo;

        firstVertex = std::stoi(vertexOne);
        secondVertex = std::stoi(vertexTwo);

        if (vertexToIDMap.find(firstVertex) == vertexToIDMap.end()) {
            vertexToIDMap[firstVertex] = idCounter;
            idToVertexMap[idCounter] = firstVertex;
            idCounter++;
        }
        if (vertexToIDMap.find(secondVertex) == vertexToIDMap.end()) {
            vertexToIDMap[secondVertex] = idCounter;
            idToVertexMap[idCounter] = secondVertex;
            idCounter++;
        }

        int firstVertexID = vertexToIDMap.find(firstVertex)->second;
        int secondVertexID = vertexToIDMap.find(secondVertex)->second;

        outFile << (firstVertexID) << ' ' << (secondVertexID) << std::endl;

        std::getline(inFile, line);
        while (!line.empty() && line.find_first_not_of(splitter) == std::string::npos) {
            std::getline(inFile, line);
        }
    }

    edgelist_partitioner_logger.log("Reformatting completed", "info");
    return outputFile;
}

void EdgeListPartitioner::loadContentData(string inputAttributeFilePath, string graphAttributeType, int graphID,
                                          string attrType = "") {
    this->graphAttributeType = graphAttributeType;

    if (graphAttributeType == Conts::GRAPH_WITH_TEXT_ATTRIBUTES) {
        std::ifstream dbFile;
        dbFile.open(inputAttributeFilePath, std::ios::binary | std::ios::in);
        edgelist_partitioner_logger.log("Processing features set", "info");

        char splitter;
        string line;

        std::getline(dbFile, line);

        if (attrType == "") {
            string firstLine = line;
            int strpos = line.find(splitter);
            string attributes = line.substr(strpos + 1, -1);

            vector<string> strArr = Utils::split(attributes, splitter);
            for (const string& value : strArr) {
                if (value.find(".") != std::string::npos) {
                    attrType = "float";
                    break;
                } else {
                    int convertedValue = stoi(value);
                    if (-125 <= convertedValue && convertedValue <= 127)
                        attrType = "int8";
                    else if (-32768 <= convertedValue && convertedValue <= 32767)
                        attrType = "int16";
                    else
                        attrType = "int32";
                }
            }
            std::cout << "Inferred feature type: " << attrType << std::endl;
        }

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
            int strpos = line.find(splitter);
            string vertex_str = line.substr(0, strpos);
            string attributes = line.substr(strpos + 1, -1);
            int vertex = stoi(vertex_str);
            attributeDataMap.insert({vertex, attributes});

            std::getline(dbFile, line);
            while (!line.empty() && line.find_first_not_of(splitter) == std::string::npos) {
                std::getline(dbFile, line);
            }
        }

        std::ifstream file;
        file.open(inputAttributeFilePath, std::ios::binary | std::ios::in);
        string str_line;

        std::getline(file, str_line);
        int count = 0;
        while (!str_line.empty()) {
            count += 1;
            std::istringstream ss(str_line);
            std::istream_iterator<std::string> begin(ss), end;
            std::vector<std::string> arrayFeatures(begin, end);
            string sqlStatement = "UPDATE graph SET feature_count = '" + std::to_string(arrayFeatures.size() - 1) +
                                  "', feature_type = '" + attrType + "' WHERE idgraph = '" + std::to_string(graphID) +
                                  "'";
            std::cout << sqlStatement << std::endl;
            std::cout << "Feature type: " << attrType << std::endl;
            edgelist_dbLock.lock();
            this->sqlite->runUpdate(sqlStatement);
            edgelist_dbLock.unlock();
            if (count == 1) {
                break;
            }
        }
    }
}

void EdgeListPartitioner::writeSerializedCompositeMasterFiles(std::string part) {
    string outputFilePartMaster =
        outputFilePath + "/" + std::to_string(this->graphID) + "_compositecentralstore_" + part;

    std::map<int, std::vector<int>> partMasterEdgeMap = compositeMasterGraphStorageMap[part];

    JasmineGraphHashMapCentralStore *hashMapCentralStore = new JasmineGraphHashMapCentralStore();
    hashMapCentralStore->storePartEdgeMap(partMasterEdgeMap, outputFilePartMaster);
    delete hashMapCentralStore;

    std::vector<std::string> graphIds = Utils::split(part, '_');

    Utils::compressFile(outputFilePartMaster);
    edgelist_masterFileMutex.lock();
    for (const std::string& graphId : graphIds) {
        compositeCentralStoreFileList[std::atoi(graphId.c_str())] = outputFilePartMaster + ".gz";
    }
    edgelist_masterFileMutex.unlock();
    edgelist_partitioner_logger.log("Serializing done for central part " + part, "info");
}
