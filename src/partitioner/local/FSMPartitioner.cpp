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

#include "FSMPartitioner.h"
#include "../../util/Utils.h"
#include "../../util/logger/Logger.h"
#include <sstream>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <algorithm>

// Include FSM framework headers
#include "../../../../fsm/src/partitioner.hpp"
#include "../../../../fsm/src/hep_partitioner.hpp"
#include "../../../../fsm/src/ne_partitioner.hpp"
#include "../../../../fsm/src/hdrf_partitioner.hpp"
#include "../../../../fsm/src/hybrid_partitioner.hpp"
#include "../../../../fsm/src/ebv_partitioner.hpp"
#include "../../../../fsm/src/dbh_partitioner.hpp"
#include "../../../../fsm/src/rand_partitioner.hpp"
#include "../../../../fsm/src/fennel_partitioner.hpp"
#include "../../../../fsm/src/bpart_partitioner.hpp"
#include "../../../../fsm/src/hybridbl_partitioner.hpp"
#include "../../../../fsm/src/fsm_partitioner.hpp"

// Declare gflags from FSM
DECLARE_int32(p);
DECLARE_string(filename);
DECLARE_string(filetype);
DECLARE_string(write);
DECLARE_string(method);
DECLARE_double(lambda);
DECLARE_double(hdf);

static Logger fsm_logger;

FSMPartitioner::FSMPartitioner(SQLiteDBInterface *sqlite) 
    : sqlite(sqlite), lastGraphID(-1) {
}

std::vector<string> FSMPartitioner::getSupportedMethods() {
    return {
        "hep", "ne", "hdrf", "hybrid", "ebv", "dbh",
        "rand", "fennel", "bpart", "hybridbl", 
        "fsm_ne", "fsm_hep"
    };
}

bool FSMPartitioner::isValidMethod(const string& method) {
    auto methods = getSupportedMethods();
    return std::find(methods.begin(), methods.end(), method) != methods.end();
}

std::map<int, std::string> FSMPartitioner::partition(
    const string& inputFilePath,
    int graphID,
    int partitionCount,
    const string& method) {
    
    return partitionWithParams(inputFilePath, graphID, partitionCount, method, 1.1, 100.0);
}

std::map<int, std::string> FSMPartitioner::partitionWithParams(
    const string& inputFilePath,
    int graphID,
    int partitionCount,
    const string& method,
    double lambda,
    double hdf) {
    
    fsm_logger.info("Starting FSM partitioning for graph " + std::to_string(graphID));
    fsm_logger.info("Method: " + method + ", Partitions: " + std::to_string(partitionCount));
    
    if (!isValidMethod(method)) {
        fsm_logger.error("Invalid FSM method: " + method);
        return {};
    }

    // Check if input file exists
    if (!std::filesystem::exists(inputFilePath)) {
        fsm_logger.error("Input file does not exist: " + inputFilePath);
        return {};
    }

    lastGraphID = graphID;
    lastMethod = method;
    
    // Create output directory for partition files
    string jasminegraphHome = Utils::getJasmineGraphProperty("org.jasminegraph.server.instance.datafolder");
    string outputDir = jasminegraphHome + "/" + std::to_string(graphID);
    
    // Create directory if it doesn't exist
    std::filesystem::create_directories(outputDir);
    
    try {
        // Set FSM flags
        FLAGS_filename = inputFilePath;
        FLAGS_p = partitionCount;
        FLAGS_method = method;
        FLAGS_filetype = "edgelist";
        FLAGS_write = "multifile";  // Write separate files for each partition
        FLAGS_lambda = lambda;
        FLAGS_hdf = hdf;
        
        fsm_logger.info("Executing FSM partitioner...");
        
        // Create appropriate partitioner based on method
        std::unique_ptr<PartitionerBase> partitioner = nullptr;
        
        if (method == "hep") {
            partitioner = std::make_unique<HepPartitioner<adj_t>>(inputFilePath, false);
        } else if (method == "ne") {
            partitioner = std::make_unique<NePartitioner<adj_t>>(inputFilePath, false);
        } else if (method == "hdrf") {
            partitioner = std::make_unique<HdrfPartitioner>(inputFilePath, false);
        } else if (method == "hybrid") {
            partitioner = std::make_unique<HybridPartitioner>(inputFilePath, false);
        } else if (method == "ebv") {
            partitioner = std::make_unique<EbvPartitioner>(inputFilePath, false);
        } else if (method == "dbh") {
            partitioner = std::make_unique<DbhPartitioner>(inputFilePath, false);
        } else if (method == "rand") {
            partitioner = std::make_unique<RandPartitioner>(inputFilePath, false);
        } else if (method == "fennel") {
            partitioner = std::make_unique<FennelPartitioner<adj_t>>(inputFilePath, false);
        } else if (method == "bpart") {
            partitioner = std::make_unique<BPartPartitioner<adj_t>>(inputFilePath, false);
        } else if (method == "hybridbl") {
            partitioner = std::make_unique<HybridBLPartitioner<adj_t>>(inputFilePath, false);
        } else if (method.substr(0, 3) == "fsm") {
            partitioner = std::make_unique<FsmPartitioner>(inputFilePath);
        }
        
        if (!partitioner) {
            fsm_logger.error("Failed to create partitioner for method: " + method);
            return {};
        }
        
        // Execute partitioning
        partitioner->split();
        
        fsm_logger.info("FSM partitioning completed successfully");
        
        // Create partition file map
        auto partitionFiles = createPartitionFileMap(outputDir, graphID, partitionCount);
        
        // Store partition metadata in database
        for (const auto& entry : partitionFiles) {
            int partitionID = entry.first;
            string partitionFile = entry.second;
            
            // Update database with partition information
            string sqlStatement = 
                "INSERT INTO partition (idpartition, graph_idgraph, partition_algorithm) "
                "VALUES ('" + std::to_string(partitionID) + "', '" + 
                std::to_string(graphID) + "', 'FSM_" + method + "')";
            
            sqlite->runInsert(sqlStatement);
        }
        
        return partitionFiles;
        
    } catch (const std::exception& e) {
        fsm_logger.error("Exception during FSM partitioning: " + string(e.what()));
        return {};
    }
}

std::map<int, std::string> FSMPartitioner::createPartitionFileMap(
    const string& outputDir,
    int graphID,
    int partitionCount) {
    
    std::map<int, std::string> partitionFiles;
    
    // FSM typically creates partition files with naming convention
    // We'll look for files in the output directory
    for (int i = 0; i < partitionCount; i++) {
        string partitionFile = outputDir + "/partition_" + std::to_string(i) + ".txt";
        partitionFiles[i] = partitionFile;
    }
    
    return partitionFiles;
}

std::map<string, string> FSMPartitioner::getPartitionStats() {
    return lastStats;
}

void FSMPartitioner::parseStats(const string& fsmOutput) {
    // Parse FSM output to extract statistics
    // This would extract metrics like replication factor, edge cut, balance, etc.
    lastStats.clear();
    
    std::istringstream iss(fsmOutput);
    string line;
    
    while (std::getline(iss, line)) {
        // Parse relevant statistics from FSM output
        if (line.find("replication factor") != string::npos) {
            size_t pos = line.find_last_of(":");
            if (pos != string::npos) {
                lastStats["replication_factor"] = line.substr(pos + 1);
            }
        } else if (line.find("Edge cut ratio") != string::npos) {
            size_t pos = line.find_last_of(":");
            if (pos != string::npos) {
                lastStats["edge_cut_ratio"] = line.substr(pos + 1);
            }
        }
    }
}

bool FSMPartitioner::executeFSM(const std::vector<string>& args, const string& outputDir) {
    // This method would execute FSM as a subprocess if needed
    // For now, we use direct library integration
    return true;
}
