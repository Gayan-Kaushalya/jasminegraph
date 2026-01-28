/**
Copyright 2024 JasminGraph Team
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

#include "XtraPulpPartitioner.h"
#include "../../util/Utils.h"
#include "../../util/logger/Logger.h"
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <unordered_map>
#include <algorithm>

extern Logger partitioner_logger;

XtraPulpPartitioner::XtraPulpPartitioner(SQLiteDBInterface *db) {
    this->sqlite = db;
}

bool XtraPulpPartitioner::isAvailable() {
    // Check if XtraPuLP executable exists
    // For now, we'll assume it's available if we can execute it
    // In production, you might want to check for the executable
    return true;
}

bool XtraPulpPartitioner::convertToXtraPulpFormat(const std::string& inputPath, 
                                                   const std::string& outputPath) {
    // XtraPuLP accepts edge list format by default
    // If the input is already in edge list format, we can copy it
    // Otherwise, we need to convert
    
    std::ifstream input(inputPath);
    std::ofstream output(outputPath);
    
    if (!input.is_open() || !output.is_open()) {
        partitioner_logger.error("Failed to open files for format conversion");
        return false;
    }
    
    std::string line;
    while (std::getline(input, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#' || line[0] == '%') {
            continue;
        }
        
        // Parse edge: source destination [weight]
        std::istringstream iss(line);
        int src, dst;
        if (iss >> src >> dst) {
            output << src << " " << dst << "\n";
        }
    }
    
    input.close();
    output.close();
    
    partitioner_logger.info("Graph converted to XtraPuLP format");
    return true;
}

std::vector<std::map<int, std::string>> XtraPulpPartitioner::createPartitionFiles(
    int graphID,
    const std::string& partitionFile,
    int numPartitions) {
    
    std::vector<std::map<int, std::string>> result;
    std::map<int, std::string> partitionFileMap;
    std::map<int, std::string> centralStoreFileMap;
    
    // Create directory for partition files
    std::string baseDir = Utils::getHomeDir() + "/.jasminegraph/tmp/" + std::to_string(graphID) + "/xtra";
    std::string command = "mkdir -p " + baseDir;
    system(command.c_str());
    
    // Read partition assignments
    std::ifstream partFile(partitionFile);
    if (!partFile.is_open()) {
        partitioner_logger.error("Failed to open partition file: " + partitionFile);
        return result;
    }
    
    std::vector<int> partitionAssignments;
    int partition;
    while (partFile >> partition) {
        partitionAssignments.push_back(partition);
    }
    partFile.close();
    
    partitioner_logger.info("Read " + std::to_string(partitionAssignments.size()) + 
                           " partition assignments");
    
    // Create partition file streams
    std::map<int, std::ofstream*> partitionStreams;
    for (int i = 0; i < numPartitions; i++) {
        std::string partFile = baseDir + "/partition_" + std::to_string(i) + ".txt";
        partitionFileMap[i] = partFile;
        partitionStreams[i] = new std::ofstream(partFile);
    }
    
    // Re-read the original graph and distribute edges
    // For now, we'll create a simple structure
    // In production, you'd read the original graph and assign edges based on vertex partitions
    
    for (auto& stream : partitionStreams) {
        stream.second->close();
        delete stream.second;
    }
    
    result.push_back(partitionFileMap);
    result.push_back(centralStoreFileMap);
    
    partitioner_logger.info("Created partition files for " + std::to_string(numPartitions) + " partitions");
    
    return result;
}

std::vector<std::map<int, std::string>> XtraPulpPartitioner::partitionWithXtraPulp(
    int graphID,
    const std::string& inputFilePath,
    int numPartitions,
    double vertexBalance,
    double edgeBalance) {
    
    partitioner_logger.info("Starting XtraPuLP partitioning for graph " + std::to_string(graphID));
    partitioner_logger.info("Input file: " + inputFilePath);
    partitioner_logger.info("Number of partitions: " + std::to_string(numPartitions));
    
    std::vector<std::map<int, std::string>> emptyResult;
    
    // Create temporary directory for XtraPuLP
    std::string tmpDir = Utils::getHomeDir() + "/.jasminegraph/tmp/" + std::to_string(graphID) + "/xtra";
    std::string mkdirCmd = "mkdir -p " + tmpDir;
    system(mkdirCmd.c_str());
    
    // Convert graph to XtraPuLP format if needed
    std::string xtraInputFile = tmpDir + "/graph.edges";
    if (!convertToXtraPulpFormat(inputFilePath, xtraInputFile)) {
        partitioner_logger.error("Failed to convert graph to XtraPuLP format");
        return emptyResult;
    }
    
    // Prepare XtraPuLP command
    // Note: This assumes XtraPuLP is compiled and in the path or we know its location
    std::string xtraPulpExe = Utils::getHomeDir() + "/../xtrapulp/0.3/xtrapulp";
    std::string outputFile = tmpDir + "/graph.part." + std::to_string(numPartitions);
    
    std::stringstream cmdStream;
    cmdStream << "cd " << tmpDir << " && ";
    cmdStream << xtraPulpExe << " ";
    cmdStream << xtraInputFile << " ";
    cmdStream << numPartitions << " ";
    cmdStream << "-v " << vertexBalance << " ";
    if (edgeBalance > 0) {
        cmdStream << "-e " << edgeBalance << " ";
    }
    cmdStream << "-o " << outputFile;
    
    std::string command = cmdStream.str();
    partitioner_logger.info("Executing XtraPuLP: " + command);
    
    int result = system(command.c_str());
    
    if (result != 0) {
        partitioner_logger.error("XtraPuLP execution failed with code: " + std::to_string(result));
        partitioner_logger.info("Note: XtraPuLP requires MPI. Use: mpirun -n <procs> " + xtraPulpExe);
        return emptyResult;
    }
    
    partitioner_logger.info("XtraPuLP partitioning completed");
    
    // Create partition files from XtraPuLP output
    return createPartitionFiles(graphID, outputFile, numPartitions);
}
