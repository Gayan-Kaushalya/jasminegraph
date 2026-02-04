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

#include "GAMEPartitioner.h"
#include "../../util/Utils.h"
#include "../../util/logger/Logger.h"
#include <sstream>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <algorithm>

// Include GAME framework headers (local to JasmineGraph)
#include "../game/Partitioner.h"
#include "../game/globalConfig.h"
#include "../game/StreamCluster.h"

static Logger game_logger;

GAMEPartitioner::GAMEPartitioner(SQLiteDBInterface *sqlite) 
    : sqlite(sqlite), lastGraphID(-1) {
    game_logger.info("GAME Partitioner initialized");
}

void GAMEPartitioner::countGraphSize(const string& inputFilePath, int& vCount, int& eCount) {
    game_logger.info("Counting graph size for: " + inputFilePath);
    
    std::unordered_set<int> vertices;
    eCount = 0;
    
    std::ifstream infile(inputFilePath);
    if (!infile.is_open()) {
        game_logger.error("Failed to open file: " + inputFilePath);
        vCount = 0;
        eCount = 0;
        return;
    }
    
    std::string line;
    while (std::getline(infile, line)) {
        std::istringstream iss(line);
        int src, dst;
        if (iss >> src >> dst) {
            vertices.insert(src);
            vertices.insert(dst);
            eCount++;
        }
    }
    
    vCount = vertices.size();
    infile.close();
    
    game_logger.info("Graph size - Vertices: " + std::to_string(vCount) + 
                    ", Edges: " + std::to_string(eCount));
}

map<int, string> GAMEPartitioner::partition(
    const string& inputFilePath,
    int graphID,
    int partitionCount,
    double alpha,
    double beta,
    int k) {
    
    game_logger.info("Starting GAME partitioning for graph " + std::to_string(graphID));
    game_logger.info("Partitions: " + std::to_string(partitionCount) + 
                    ", alpha: " + std::to_string(alpha) + 
                    ", beta: " + std::to_string(beta) + 
                    ", k: " + std::to_string(k));
    
    lastGraphID = graphID;
    lastMethod = "GAME";
    
    // Validate input file
    if (!std::filesystem::exists(inputFilePath)) {
        game_logger.error("Input file does not exist: " + inputFilePath);
        return {};
    }
    
    // Create output directory
    string jasminegraphHome = Utils::getJasmineGraphProperty("org.jasminegraph.server.instance.datafolder");
    string outputDir = jasminegraphHome + "/" + std::to_string(graphID);
    std::filesystem::create_directories(outputDir);
    
    try {
        // Count graph size
        int vCount = 0, eCount = 0;
        countGraphSize(inputFilePath, vCount, eCount);
        
        if (vCount == 0 || eCount == 0) {
            game_logger.error("Invalid graph: vCount=" + std::to_string(vCount) + 
                            ", eCount=" + std::to_string(eCount));
            return {};
        }
        
        // Create GAME configuration
        GlobalConfig config;
        config.inputGraphPath = inputFilePath;
        config.vCount = vCount;
        config.eCount = eCount;
        config.partitionNum = partitionCount;
        config.alpha = alpha;
        config.beta = beta;
        config.k = k;
        config.batchSize = 204800;  // Default batch size
        config.threads = 16;  // Use all available threads
        
        game_logger.info("Executing GAME clustering...");
        
        // Perform streaming clustering
        StreamCluster streamCluster(config);
        streamCluster.startStreamCluster();
        streamCluster.computeHybridInfo();
        
        game_logger.info("Big clusters: " + std::to_string(streamCluster.getClusterList_B().size()));
        game_logger.info("Small clusters: " + std::to_string(streamCluster.getClusterList_S().size()));
        
        // Perform game-theoretic partitioning
        game_logger.info("Starting Stackelberg game partitioning...");
        Partitioner partitioner(streamCluster, config);
        partitioner.startStackelbergGame();
        
        // Calculate statistics
        double replicateFactor = partitioner.getReplicateFactor();
        double loadBalance = partitioner.getLoadBalance();
        
        lastStats["replicate_factor"] = std::to_string(replicateFactor);
        lastStats["load_balance"] = std::to_string(loadBalance);
        lastStats["num_vertices"] = std::to_string(vCount);
        lastStats["num_edges"] = std::to_string(eCount);
        lastStats["num_partitions"] = std::to_string(partitionCount);
        
        game_logger.info("GAME partitioning completed successfully");
        game_logger.info("Replication factor: " + std::to_string(replicateFactor));
        game_logger.info("Load balance: " + std::to_string(loadBalance));
        
        // Create partition file map (GAME writes files directly)
        auto partitionFiles = createPartitionFileMap(outputDir, graphID, partitionCount);
        
        // Store partition metadata in database
        for (const auto& entry : partitionFiles) {
            int partitionID = entry.first;
            string partitionFile = entry.second;
            
            string sqlStatement = 
                "INSERT INTO partition (idpartition, graph_idgraph, partition_algorithm) "
                "VALUES ('" + std::to_string(partitionID) + "', '" + 
                std::to_string(graphID) + "', 'GAME')";
            
            sqlite->runInsert(sqlStatement);
        }
        
        return partitionFiles;
        
    } catch (const std::exception& e) {
        game_logger.error("Exception during GAME partitioning: " + string(e.what()));
        return {};
    }
}

map<int, string> GAMEPartitioner::createPartitionFileMap(
    const string& outputDir,
    int graphID,
    int partitionCount) {
    
    map<int, string> partitionFiles;
    
    for (int i = 0; i < partitionCount; i++) {
        string partitionFile = outputDir + "/partition_" + std::to_string(i) + ".txt";
        partitionFiles[i] = partitionFile;
    }
    
    return partitionFiles;
}

map<string, string> GAMEPartitioner::getPartitionStats() {
    return lastStats;
}
