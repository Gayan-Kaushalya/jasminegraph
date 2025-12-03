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

#include "GraphSizeEstimator.h"
#include "Utils.h"
#include "logger/Logger.h"
#include <fstream>
#include <sstream>
#include <set>
#include <sys/stat.h>

Logger graphSizeEstimator_logger;

long GraphSizeEstimator::estimateFromFile(const string& filePath) {
    graphSizeEstimator_logger.log("Estimating graph size from file: " + filePath, "info");
    
    // First try to get basic file size
    long fileSize = getFileSize(filePath);
    if (fileSize <= 0) {
        graphSizeEstimator_logger.log("Could not get file size for: " + filePath, "error");
        return 0;
    }
    
    // Parse the file to get vertex and edge counts
    long vertexCount = 0, edgeCount = 0;
    if (parseGraphFile(filePath, vertexCount, edgeCount)) {
        graphSizeEstimator_logger.log("Parsed graph - Vertices: " + to_string(vertexCount) + 
                                   ", Edges: " + to_string(edgeCount), "info");
        return estimateFromCounts(vertexCount, edgeCount);
    } else {
        // Fallback: estimate based on file size
        // Assume each edge takes about 20-30 bytes on average in memory (including overhead)
        graphSizeEstimator_logger.log("Using file size estimation fallback", "warn");
        return fileSize * 3; // Rough multiplier for in-memory representation
    }
}

long GraphSizeEstimator::estimateFromCounts(long vertexCount, long edgeCount, bool hasFeatures, int featureCount) {
    graphSizeEstimator_logger.log("Estimating graph size from counts - V: " + to_string(vertexCount) + 
                               ", E: " + to_string(edgeCount), "info");
    
    // Basic graph structure memory
    // Each edge: 2 vertex IDs (8 bytes each) = 16 bytes
    long edgeMemory = edgeCount * 16;
    
    // Vertex storage: ID + adjacency list pointer + metadata
    long vertexMemory = vertexCount * 64; // 64 bytes per vertex
    
    // Adjacency list overhead (pointers, containers)
    long adjacencyOverhead = edgeCount * 8; // 8 bytes per edge for list entries
    
    // Feature memory (if applicable)
    long featureMemory = 0;
    if (hasFeatures && featureCount > 0) {
        // Assuming float features (4 bytes each)
        featureMemory = vertexCount * featureCount * 4;
    }
    
    // Basic memory calculation
    long baseSize = edgeMemory + vertexMemory + adjacencyOverhead + featureMemory;
    
    // Add overhead for graph processing structures
    long overhead = calculateOverhead(baseSize);
    
    long totalSize = baseSize + overhead;
    
    graphSizeEstimator_logger.log("Size estimation - Base: " + to_string(baseSize) + 
                               " bytes, Overhead: " + to_string(overhead) + 
                               " bytes, Total: " + to_string(totalSize) + " bytes", "info");
    
    return totalSize;
}

long GraphSizeEstimator::getFileSize(const string& filePath) {
    struct stat stat_buf;
    int rc = stat(filePath.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_size : -1;
}

long GraphSizeEstimator::countLinesInFile(const string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return 0;
    }
    
    long lineCount = 0;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line[0] != '#') { // Skip comments
            lineCount++;
        }
    }
    
    file.close();
    return lineCount;
}

bool GraphSizeEstimator::parseGraphFile(const string& filePath, long& vertexCount, long& edgeCount) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        graphSizeEstimator_logger.log("Could not open file: " + filePath, "error");
        return false;
    }
    
    std::set<long> vertices;
    edgeCount = 0;
    std::string line;
    char delimiter = ' '; // Default delimiter
    
    // Try to determine delimiter from first non-comment line
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        if (line.find('\t') != std::string::npos) {
            delimiter = '\t';
        } else if (line.find(',') != std::string::npos) {
            delimiter = ',';
        }
        break;
    }
    
    // Reset file to beginning
    file.clear();
    file.seekg(0, std::ios::beg);
    
    // Parse the file
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue; // Skip empty lines and comments
        
        std::istringstream iss(line);
        std::string sourceStr, targetStr;
        
        if (delimiter == ' ') {
            if (!(iss >> sourceStr >> targetStr)) continue;
        } else {
            if (!std::getline(iss, sourceStr, delimiter) || 
                !std::getline(iss, targetStr, delimiter)) continue;
        }
        
        try {
            long source = std::stol(sourceStr);
            long target = std::stol(targetStr);
            
            vertices.insert(source);
            vertices.insert(target);
            edgeCount++;
            
        } catch (const std::exception& e) {
            // Skip malformed lines
            continue;
        }
    }
    
    file.close();
    vertexCount = vertices.size();
    
    graphSizeEstimator_logger.log("Parsed graph file - Found " + to_string(vertexCount) + 
                               " unique vertices and " + to_string(edgeCount) + " edges", "info");
    
    return vertexCount > 0 && edgeCount > 0;
}

long GraphSizeEstimator::calculateOverhead(long baseSize) {
    // Graph processing overhead includes:
    // - Hash tables/maps for vertex lookups
    // - Temporary data structures during algorithms
    // - Memory fragmentation
    // - JVM/runtime overhead (if applicable)
    
    // Conservative estimate: 50% overhead
    return baseSize / 2;
}