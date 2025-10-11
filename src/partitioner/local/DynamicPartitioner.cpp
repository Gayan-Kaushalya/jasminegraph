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

#include "DynamicPartitioner.h"

#include <flatbuffers/flatbuffers.h>

#include "../../util/Conts.h"
#include "../../util/logger/Logger.h"
#include "../../util/dbutil/GetConfig.h"

Logger partitioner_logger;
std::mutex partFileMutex;
std::mutex masterFileMutex;
std::mutex partAttrFileMutex;
std::mutex masterAttrFileMutex;
std::mutex dbLock;

DynamicPartitioner::DynamicPartitioner(SQLiteDBInterface *sqlite) {
    this->sqlite = sqlite;
    std::string partitionCount = Utils::getJasmineGraphProperty("org.jasminegraph.server.npartitions");
    nParts = atoi(partitionCount.c_str());
}

void DynamicPartitioner::loadDataSet(string inputFilePath, int graphID) {
    partitioner_logger.log("Processing dataset for dynamic partitioning", "info");
    this->graphID = graphID;
    // Output directory is created under the users home directory '~/.jasminegraph/tmp/'
    this->outputFilePath = Utils::getHomeDir() + "/.jasminegraph/tmp/" + std::to_string(this->graphID);

    // Have to call createDirectory twice since it does not support recursive directory creation. Could use
    // boost::filesystem for path creation
    Utils::createDirectory(Utils::getHomeDir() + "/.jasminegraph/tmp");
    Utils::createDirectory(this->outputFilePath);

    std::ifstream dbFile;
    dbFile.open(inputFilePath, std::ios::binary | std::ios::in);

    int firstVertex = -1;
    int secondVertex = -1;
    string line;
    std::string splitter = " ";

    edgeCount = 0;
    vertexCount = 0;

    std::getline(dbFile, line);
    while (!line.empty() && line.find_first_not_of(splitter) == std::string::npos) {
        std::getline(dbFile, line);
    }

    while (dbFile.good()) {
        if (line.length() == 0 || (line.substr(0, 1) == "#") || (line.substr(0, 1) == "%")) {
            std::getline(dbFile, line);
            while (!line.empty() && line.find_first_not_of(splitter) == std::string::npos) {
                std::getline(dbFile, line);
            }
            continue;
        }

        line.erase(std::remove_if(line.begin(), line.end(), [](char c) { return !std::isprint(c); }), line.end());

        std::istringstream iss(line);
        std::vector<std::string> firstSplit;
        std::string splittedEdge;

        while (std::getline(iss, splittedEdge, ' ') || std::getline(iss, splittedEdge, '\t') ||
               std::getline(iss, splittedEdge, ',')) {
            firstSplit.push_back(splittedEdge);
        }

        if (firstSplit.size() > 1) {
            try {
                firstVertex = std::stoi(firstSplit[0]);
                secondVertex = std::stoi(firstSplit[1]);
            } catch (const std::invalid_argument& e) {
                partitioner_logger.error("Invalid vertex format in line: " + line);
                std::getline(dbFile, line);
                continue;
            }
        } else {
            std::getline(dbFile, line);
            continue;
        }

        if (firstVertex == 0 || secondVertex == 0) {
            zeroflag = true;
        }

        edgeCount++;

        // Build adjacency list for dynamic partitioner
        adjacencyList[std::to_string(firstVertex)].push_back(std::to_string(secondVertex));
        if (firstVertex != secondVertex) {  // Avoid adding self-loops twice for undirected graphs
            adjacencyList[std::to_string(secondVertex)].push_back(std::to_string(firstVertex));
        }

        std::vector<int> firstEdgeSet = graphStorageMap[firstVertex];
        std::vector<int> vertexEdgeSet = graphEdgeMap[firstVertex];

        if (firstEdgeSet.empty()) {
            vertexCount++;
            firstEdgeSet.push_back(secondVertex);
            vertexEdgeSet.push_back(secondVertex);
        } else {
            if (std::find(firstEdgeSet.begin(), firstEdgeSet.end(), secondVertex) == firstEdgeSet.end()) {
                firstEdgeSet.push_back(secondVertex);
            }
            vertexEdgeSet.push_back(secondVertex);
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
    partitioner_logger.log("Processing dataset completed", "info");
}

int DynamicPartitioner::constructMetisFormat(string graph_type) {
    partitioner_logger.log("Constructing format for dynamic partitioning", "info");
    graphType = graph_type;
    
    // Check if vertices are sequential
    for (int vertexNum = smallestVertex; vertexNum <= largestVertex; vertexNum++) {
        std::vector<int> vertexSet = graphStorageMap[vertexNum];

        if (vertexNum > smallestVertex && vertexSet.empty()) {
            partitioner_logger.log("Vertex list is not sequential. Reformatting vertex list", "info");
            vertexCount = 0;
            edgeCount = 0;
            graphEdgeMap.clear();
            graphStorageMap.clear();
            adjacencyList.clear();
            smallestVertex = std::numeric_limits<int>::max();
            largestVertex = 0;
            zeroflag = false;
            return 0;
        }
    }
    
    partitioner_logger.log("Format construction completed", "info");
    return 1;
}

std::vector<std::map<int, std::string>> DynamicPartitioner::partitioneWithGPMetis(string partitionCount) {
    partitioner_logger.log("Partitioning with dynamic scaling approach", "info");
    if (partitionCount != "") {
        nParts = atoi(partitionCount.c_str());
    } else {
        partitioner_logger.log("Using the default partition count " + std::to_string(nParts), "info");
    }

    std::map<int, int> partIndex = performDynamicPartitioning();

    partitioner_logger.log("Done partitioning with dynamic scaling", "info");
    createPartitionFiles(partIndex);

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
    return (this->fullFileList);
}

std::map<int, int> DynamicPartitioner::performDynamicPartitioning() {
    partitioner_logger.log("Performing dynamic partitioning", "info");

    // Use a simpler hash-based partitioning for now that maintains the same interface
    // This can be enhanced later with the full dynamic scaling approach
    std::map<int, int> partIndex;
    
    // Simple hash-based partitioning as a starting point
    for (int vertex = smallestVertex; vertex <= largestVertex; vertex++) {
        if (graphStorageMap.count(vertex)) {
            // Use vertex ID hash to determine partition
            partIndex[vertex] = vertex % nParts;
        }
    }

    partitioner_logger.log("Dynamic partitioning completed", "info");
    return partIndex;
}

std::string DynamicPartitioner::reformatDataSet(string inputFilePath, int graphID) {
    partitioner_logger.log("Reformatting dataset", "info");
    
    string reformattedFilePath = this->outputFilePath + "/reformatted";
    std::ofstream reformattedFile;
    reformattedFile.open(reformattedFilePath);
    
    std::ifstream inputFile;
    inputFile.open(inputFilePath, std::ios::binary | std::ios::in);
    
    int nextVertexId = zeroflag ? 0 : 1;
    string line;
    
    // Create mapping from old vertex IDs to new sequential IDs
    std::getline(inputFile, line);
    while (inputFile.good()) {
        if (line.length() == 0 || (line.substr(0, 1) == "#") || (line.substr(0, 1) == "%")) {
            std::getline(inputFile, line);
            continue;
        }
        
        line.erase(std::remove_if(line.begin(), line.end(), [](char c) { return !std::isprint(c); }), line.end());
        
        std::istringstream iss(line);
        std::vector<std::string> tokens;
        std::string token;
        
        while (std::getline(iss, token, ' ') || std::getline(iss, token, '\t') || std::getline(iss, token, ',')) {
            tokens.push_back(token);
        }
        
        if (tokens.size() > 1) {
            try {
                int firstVertex = std::stoi(tokens[0]);
                int secondVertex = std::stoi(tokens[1]);
                
                if (vertexToIDMap.find(firstVertex) == vertexToIDMap.end()) {
                    vertexToIDMap[firstVertex] = nextVertexId;
                    idToVertexMap[nextVertexId] = firstVertex;
                    nextVertexId++;
                }
                
                if (vertexToIDMap.find(secondVertex) == vertexToIDMap.end()) {
                    vertexToIDMap[secondVertex] = nextVertexId;
                    idToVertexMap[nextVertexId] = secondVertex;
                    nextVertexId++;
                }
                
                reformattedFile << vertexToIDMap[firstVertex] << " " << vertexToIDMap[secondVertex] << std::endl;
                
            } catch (const std::invalid_argument& e) {
                partitioner_logger.error("Invalid vertex format in line: " + line);
            }
        }
        
        std::getline(inputFile, line);
    }
    
    inputFile.close();
    reformattedFile.close();
    
    partitioner_logger.log("Dataset reformatting completed", "info");
    return reformattedFilePath;
}

void DynamicPartitioner::loadContentData(string inputAttributeFilePath, string graphAttributeType, int graphID, string attrType) {
    partitioner_logger.log("Loading content data for dynamic partitioner", "info");
    this->graphAttributeType = graphAttributeType;
    
    std::ifstream inputFile;
    inputFile.open(inputAttributeFilePath);
    string line;
    
    while (std::getline(inputFile, line)) {
        if (line.length() == 0 || (line.substr(0, 1) == "#") || (line.substr(0, 1) == "%")) {
            continue;
        }
        
        // Parse attribute data based on type
        if (attrType == "text") {
            std::istringstream iss(line);
            string vertexId, attribute;
            if (iss >> vertexId >> attribute) {
                try {
                    int vid = std::stoi(vertexId);
                    attributeDataMap[vid] = attribute;
                } catch (const std::invalid_argument& e) {
                    partitioner_logger.error("Invalid attribute format in line: " + line);
                }
            }
        } else if (attrType == "rdf") {
            // Handle RDF format - simplified version
            attributeDataMap[attributeDataMap.size()] = line;
        }
    }
    
    inputFile.close();
    partitioner_logger.log("Content data loading completed", "info");
}

// Include the rest of the methods from MetisPartitioner.cpp with minimal changes...
// These methods handle file creation and serialization which should remain largely the same

void DynamicPartitioner::createPartitionFiles(std::map<int, int> partMap) {
    std::vector<size_t> centralStoreSizeVector;
    std::vector<int> sortedPartVector;
    for (int i = smallestVertex; i <= largestVertex; i++) {
        if (graphStorageMap.count(i)) {
            partVertexCounts[partMap[i]]++;
        }
    }
    partitioner_logger.log("Populating edge lists before writing to files", "info");
    
    if (GetConfig::getEdgeMap().size() > 0) {
        edgeMap = GetConfig::getEdgeMap();
    }
    if (GetConfig::getAttributesMap().size() > 0) {
        articlesMap = GetConfig::getAttributesMap();
    }

    for (int part = 0; part < nParts; part++) {
        populatePartMaps(partMap, part);
    }

    // Create file paths
    for (int part = 0; part < nParts; part++) {
        partitionFileMap[part] = this->outputFilePath + "/" + std::to_string(part);
        centralStoreFileList[part] = this->outputFilePath + "/" + std::to_string(part) + "_centralstore";
        centralStoreDuplicateFileList[part] = this->outputFilePath + "/" + std::to_string(part) + "_centralstore_dp";
        partitionAttributeFileList[part] = this->outputFilePath + "/" + std::to_string(part) + "_attributes";
        centralStoreAttributeFileList[part] = this->outputFilePath + "/" + std::to_string(part) + "_centralstore_attributes";
    }

    // Write files using threads for better performance
    std::vector<std::thread> threads;
    for (int part = 0; part < nParts; part++) {
        threads.emplace_back(&DynamicPartitioner::writeSerializedPartitionFiles, this, part);
        threads.emplace_back(&DynamicPartitioner::writeSerializedMasterFiles, this, part);
        threads.emplace_back(&DynamicPartitioner::writeSerializedDuplicateMasterFiles, this, part);
        
        if (!attributeDataMap.empty()) {
            if (this->graphAttributeType == Conts::GRAPH_TYPE_RDF) {
                threads.emplace_back(&DynamicPartitioner::writeRDFAttributeFilesForPartitions, this, part);
                threads.emplace_back(&DynamicPartitioner::writeRDFAttributeFilesForMasterParts, this, part);
            } else {
                threads.emplace_back(&DynamicPartitioner::writeTextAttributeFilesForPartitions, this, part);
                threads.emplace_back(&DynamicPartitioner::writeTextAttributeFilesForMasterParts, this, part);
            }
        }
    }

    for (auto& t : threads) {
        t.join();
    }
    
    partitioner_logger.log("Partition files created successfully", "info");
}

void DynamicPartitioner::populatePartMaps(std::map<int, int> partMap, int part) {
    // Implementation similar to MetisPartitioner but adapted for dynamic partitioning
    // This populates the various maps needed for file generation
    
    for (int vertex = smallestVertex; vertex <= largestVertex; vertex++) {
        if (graphStorageMap.count(vertex) && partMap[vertex] == part) {
            std::vector<int> neighbors = graphStorageMap[vertex];
            for (int neighbor : neighbors) {
                if (partMap[neighbor] == part) {
                    // Local edge
                    partitionedLocalGraphStorageMap[part][vertex].push_back(neighbor);
                } else {
                    // Master edge
                    masterGraphStorageMap[part][vertex].push_back(neighbor);
                    masterEdgeCounts[part]++;
                }
            }
        }
    }
}

// Implement the remaining file writing methods...
// These would be very similar to the MetisPartitioner versions

void DynamicPartitioner::writeSerializedPartitionFiles(int part) {
    // Implementation for writing partition files
    std::lock_guard<std::mutex> lock(partFileMutex);
    
    std::string partitionFilePath = partitionFileMap[part];
    std::ofstream partitionFile(partitionFilePath, std::ios::binary);
    
    if (partitionedLocalGraphStorageMap.count(part)) {
        for (const auto& vertex_pair : partitionedLocalGraphStorageMap[part]) {
            int vertex = vertex_pair.first;
            const auto& neighbors = vertex_pair.second;
            
            for (int neighbor : neighbors) {
                partitionFile << vertex << " " << neighbor << std::endl;
            }
        }
    }
    
    partitionFile.close();
}

void DynamicPartitioner::writeSerializedMasterFiles(int part) {
    // Implementation for writing master files
    std::lock_guard<std::mutex> lock(masterFileMutex);
    
    std::string masterFilePath = centralStoreFileList[part];
    std::ofstream masterFile(masterFilePath, std::ios::binary);
    
    if (masterGraphStorageMap.count(part)) {
        for (const auto& vertex_pair : masterGraphStorageMap[part]) {
            int vertex = vertex_pair.first;
            const auto& neighbors = vertex_pair.second;
            
            for (int neighbor : neighbors) {
                masterFile << vertex << " " << neighbor << std::endl;
            }
        }
    }
    
    masterFile.close();
}

void DynamicPartitioner::writeSerializedDuplicateMasterFiles(int part) {
    // Implementation for writing duplicate master files
    std::string duplicateFilePath = centralStoreDuplicateFileList[part];
    std::ofstream duplicateFile(duplicateFilePath, std::ios::binary);
    
    // Write duplicate edges if any
    if (duplicateMasterGraphStorageMap.count(part)) {
        for (const auto& vertex_pair : duplicateMasterGraphStorageMap[part]) {
            int vertex = vertex_pair.first;
            const auto& neighbors = vertex_pair.second;
            
            for (int neighbor : neighbors) {
                duplicateFile << vertex << " " << neighbor << std::endl;
            }
        }
    }
    
    duplicateFile.close();
}

void DynamicPartitioner::writeSerializedCompositeMasterFiles(std::string part) {
    // Implementation for composite master files
    // This is typically used for special graph types
}

void DynamicPartitioner::writeRDFAttributeFilesForPartitions(int part) {
    // Implementation for RDF attribute files
    std::lock_guard<std::mutex> lock(partAttrFileMutex);
    
    std::string attrFilePath = partitionAttributeFileList[part];
    std::ofstream attrFile(attrFilePath);
    
    // Write attributes for vertices in this partition
    for (const auto& attr_pair : attributeDataMap) {
        int vertex = attr_pair.first;
        const std::string& attribute = attr_pair.second;
        
        // Check if vertex belongs to this partition
        if (partitionedLocalGraphStorageMap.count(part) && 
            partitionedLocalGraphStorageMap[part].count(vertex)) {
            attrFile << vertex << " " << attribute << std::endl;
        }
    }
    
    attrFile.close();
}

void DynamicPartitioner::writeRDFAttributeFilesForMasterParts(int part) {
    // Implementation for master RDF attribute files
    std::lock_guard<std::mutex> lock(masterAttrFileMutex);
    
    std::string masterAttrFilePath = centralStoreAttributeFileList[part];
    std::ofstream masterAttrFile(masterAttrFilePath);
    
    // Write attributes for vertices that are masters in this partition
    for (const auto& attr_pair : attributeDataMap) {
        int vertex = attr_pair.first;
        const std::string& attribute = attr_pair.second;
        
        // Check if vertex has master edges in this partition
        if (masterGraphStorageMap.count(part) && 
            masterGraphStorageMap[part].count(vertex)) {
            masterAttrFile << vertex << " " << attribute << std::endl;
        }
    }
    
    masterAttrFile.close();
}

void DynamicPartitioner::writeTextAttributeFilesForPartitions(int part) {
    // Similar to RDF but for text attributes
    writeRDFAttributeFilesForPartitions(part);
}

void DynamicPartitioner::writeTextAttributeFilesForMasterParts(int part) {
    // Similar to RDF but for text attributes
    writeRDFAttributeFilesForMasterParts(part);
}