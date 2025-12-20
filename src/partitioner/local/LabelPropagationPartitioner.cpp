/**
Copyright 2025 JasmineGraph Team
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

#include "LabelPropagationPartitioner.h"

#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <random>

#include "../../util/Utils.h"
#include "../../util/logger/Logger.h"

Logger lpa_logger;

LabelPropagationPartitioner::LabelPropagationPartitioner(SQLiteDBInterface *sqlite) {
    this->sqlite = sqlite;
    this->maxIterations = 100;
    this->vertexCount = 0;
    this->edgeCount = 0;
    this->zeroflag = false;
}

void LabelPropagationPartitioner::loadDataSet(string inputFilePath, int graphID) {
    lpa_logger.log("Loading dataset for label propagation partitioning", "info");
    this->graphID = graphID;
    this->inputFilePath = inputFilePath;
    this->outputFilePath = Utils::getHomeDir() + "/.jasminegraph/tmp/" + std::to_string(this->graphID);
    
    Utils::createDirectory(Utils::getHomeDir() + "/.jasminegraph/tmp");
    Utils::createDirectory(this->outputFilePath);
    
    loadGraph();
}

void LabelPropagationPartitioner::loadGraph() {
    std::ifstream dbFile(inputFilePath);
    if (!dbFile.is_open()) {
        lpa_logger.log("Failed to open input file: " + inputFilePath, "error");
        return;
    }
    
    string line;
    char splitter = ' ';
    
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
        
        int firstVertex = std::stoi(vertexOne);
        int secondVertex = std::stoi(vertexTwo);
        
        if (!zeroflag) {
            if (firstVertex == 0 || secondVertex == 0) {
                zeroflag = true;
                lpa_logger.log("Graph has zero vertex", "info");
            }
        }
        
        adjacencyList[firstVertex].push_back(secondVertex);
        adjacencyList[secondVertex].push_back(firstVertex);
        
        edgeCount++;
        
        if (!std::getline(dbFile, line)) {
            break;
        }
    }
    
    vertexCount = adjacencyList.size();
    lpa_logger.log("Loaded graph: " + std::to_string(vertexCount) + " vertices, " + 
                   std::to_string(edgeCount) + " edges", "info");
    
    dbFile.close();
}

void LabelPropagationPartitioner::initializeLabels() {
    lpa_logger.log("Initializing node labels", "info");
    
    for (const auto& pair : adjacencyList) {
        int nodeId = pair.first;
        nodeLabels[nodeId] = nodeId;
        uniqueLabels.insert(nodeId);
    }
}

int LabelPropagationPartitioner::getMostFrequentLabel(int nodeId) {
    std::unordered_map<int, int> labelCount;
    
    for (int neighbor : adjacencyList[nodeId]) {
        int label = nodeLabels[neighbor];
        labelCount[label]++;
    }
    
    if (labelCount.empty()) {
        return nodeLabels[nodeId];
    }
    
    int maxCount = 0;
    std::vector<int> maxLabels;
    
    for (const auto& pair : labelCount) {
        if (pair.second > maxCount) {
            maxCount = pair.second;
            maxLabels.clear();
            maxLabels.push_back(pair.first);
        } else if (pair.second == maxCount) {
            maxLabels.push_back(pair.first);
        }
    }
    
    if (maxLabels.size() == 1) {
        return maxLabels[0];
    }
    
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, maxLabels.size() - 1);
    return maxLabels[dis(gen)];
}

void LabelPropagationPartitioner::propagateLabels() {
    lpa_logger.log("Starting label propagation", "info");
    
    std::vector<int> nodeOrder;
    for (const auto& pair : adjacencyList) {
        nodeOrder.push_back(pair.first);
    }
    
    for (int iteration = 0; iteration < maxIterations; iteration++) {
        std::random_device rd;
        std::mt19937 g(rd());
        std::shuffle(nodeOrder.begin(), nodeOrder.end(), g);
        
        bool changed = false;
        
        for (int nodeId : nodeOrder) {
            int newLabel = getMostFrequentLabel(nodeId);
            if (newLabel != nodeLabels[nodeId]) {
                nodeLabels[nodeId] = newLabel;
                changed = true;
            }
        }
        
        if (!changed) {
            lpa_logger.log("Converged at iteration " + std::to_string(iteration + 1), "info");
            break;
        }
    }
    
    uniqueLabels.clear();
    for (const auto& pair : nodeLabels) {
        uniqueLabels.insert(pair.second);
    }
    
    lpa_logger.log("Label propagation complete. Found " + std::to_string(uniqueLabels.size()) + 
                   " partitions", "info");
}

std::vector<std::map<int, std::string>> LabelPropagationPartitioner::partition() {
    lpa_logger.log("Starting label propagation partitioning", "info");
    
    initializeLabels();
    propagateLabels();
    writePartitions();
    
    std::vector<std::map<int, std::string>> result;
    std::map<int, int> labelToPartitionId;
    int partitionId = 0;
    
    for (int label : uniqueLabels) {
        labelToPartitionId[label] = partitionId++;
    }
    
    for (int i = 0; i < uniqueLabels.size(); i++) {
        std::map<int, std::string> partitionMap;
        result.push_back(partitionMap);
    }
    
    for (const auto& pair : nodeLabels) {
        int nodeId = pair.first;
        int label = pair.second;
        int partId = labelToPartitionId[label];
        result[partId][nodeId] = std::to_string(nodeId);
    }
    
    return result;
}

void LabelPropagationPartitioner::writePartitions() {
    std::map<int, std::vector<int>> partitions;
    
    for (const auto& pair : nodeLabels) {
        int nodeId = pair.first;
        int label = pair.second;
        partitions[label].push_back(nodeId);
    }
    
    std::map<int, int> labelToPartitionId;
    int partitionId = 0;
    for (const auto& pair : partitions) {
        labelToPartitionId[pair.first] = partitionId++;
    }
    
    for (const auto& pair : partitions) {
        int label = pair.first;
        int partId = labelToPartitionId[label];
        const std::vector<int>& nodes = pair.second;
        
        string partitionFileName = outputFilePath + "/" + std::to_string(graphID) + "_" + 
                                   std::to_string(partId);
        std::ofstream partitionFile(partitionFileName);
        
        if (partitionFile.is_open()) {
            for (int nodeId : nodes) {
                for (int neighbor : adjacencyList[nodeId]) {
                    partitionFile << nodeId << " " << neighbor << "\n";
                }
            }
            partitionFile.close();
        }
    }
    
    lpa_logger.log("Written " + std::to_string(partitions.size()) + " partition files", "info");
}

int LabelPropagationPartitioner::getPartitionCount() {
    return uniqueLabels.size();
}
