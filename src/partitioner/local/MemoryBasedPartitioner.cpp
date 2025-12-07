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

#include "MemoryBasedPartitioner.h"
#include "../../util/logger/Logger.h"
#include "../../util/Utils.h"
#include "../../util/GraphSizeEstimator.h"
#include "../../performance/metrics/StatisticCollector.h"    /// Make sure to change this when merging to master branch
#include <cmath>
#include <algorithm>
#include <iostream>

Logger memoryPartitioner_logger;

MemoryBasedPartitioner::MemoryBasedPartitioner(SQLiteDBInterface *sqlite) {
    this->sqlite = sqlite;
    this->performanceDb = new PerformanceSQLiteDBInterface();
    this->performanceDb->init();
}

int MemoryBasedPartitioner::calculatePartitionCount(const string& graphId, long graphSize) {
    memoryPartitioner_logger.log("Calculating partition count based on memory constraints", "info");
    
    // Step 1: Get memory allocated per CPU core for each worker
    map<string, long> workerMemoryMap = getWorkerMemoryPerCore();
    
    if (workerMemoryMap.empty()) {
        memoryPartitioner_logger.log("No workers found, using default partition count of 2", "warn");
        return 2;
    }
    
    // Step 2: Find minimum memory across all worker cores (g_min)
    long g_min = getMinimumWorkerMemory(workerMemoryMap);
    memoryPartitioner_logger.log("Minimum worker memory per core (g_min): " + to_string(g_min) + " bytes", "info");
    
    // Step 3: Get graph memory size (||G||)
    long graphMemorySize = graphSize > 0 ? graphSize : estimateGraphMemorySize(graphId);
    memoryPartitioner_logger.log("Graph memory size (||G||): " + to_string(graphMemorySize) + " bytes", "info");
    
    // Step 4: Calculate required partitions using s = ceil(||G|| / g_min)
    if (g_min <= 0) {
        memoryPartitioner_logger.log("Invalid minimum memory, using default partition count of 2", "error");
        return 2;
    }
    
    int partitionCount = static_cast<int>(std::ceil(static_cast<double>(graphMemorySize) / static_cast<double>(g_min)));
    
    // Ensure minimum of 2 partitions
    if (partitionCount < 2) {
        partitionCount = 2;
    }
    
    memoryPartitioner_logger.log("Calculated partition count (s): " + to_string(partitionCount), "info");
    
    return partitionCount;
}

map<string, long> MemoryBasedPartitioner::getWorkerMemoryPerCore() {
    map<string, long> workerMemoryMap;
    
    // Get active workers
    vector<string> workers = getActiveWorkers();
    
    for (const string& worker : workers) {
        // Get total memory for worker
        long totalMemory = getWorkerTotalMemory(worker);
        
        // Get core count for worker
        int coreCount = getWorkerCoreCount(worker);
        
        if (coreCount > 0 && totalMemory > 0) {
            // Calculate memory per core (convert KB to bytes)
            long memoryPerCore = (totalMemory * 1024) / coreCount;
            workerMemoryMap[worker] = memoryPerCore;
            
            memoryPartitioner_logger.log("Worker " + worker + ": " + to_string(memoryPerCore) + 
                                       " bytes per core (" + to_string(totalMemory) + " KB total, " + 
                                       to_string(coreCount) + " cores)", "info");
        } else {
            memoryPartitioner_logger.log("Invalid memory or core count for worker " + worker, "warn");
        }
    }
    
    return workerMemoryMap;
}

long MemoryBasedPartitioner::getMinimumWorkerMemory(const map<string, long>& workerMemoryMap) {
    if (workerMemoryMap.empty()) {
        return 0;
    }
    
    long minMemory = LONG_MAX;
    string minWorker;
    
    for (const auto& entry : workerMemoryMap) {
        if (entry.second < minMemory) {
            minMemory = entry.second;
            minWorker = entry.first;
        }
    }
    
    memoryPartitioner_logger.log("Minimum memory found on worker " + minWorker + ": " + 
                               to_string(minMemory) + " bytes per core", "info");
    
    return minMemory;
}

long MemoryBasedPartitioner::estimateGraphMemorySize(const string& graphId) {
    memoryPartitioner_logger.log("Estimating graph memory size for graph " + graphId, "info");
    
    // Get vertex and edge counts from database
    string sqlStatement = "SELECT vertexcount, edgecount FROM graph WHERE idgraph = " + graphId;
    vector<vector<pair<string, string>>> result = sqlite->runSelect(sqlStatement);
    
    if (result.empty()) {
        memoryPartitioner_logger.log("Graph not found in database", "error");
        return 0;
    }
    
    long vertexCount = stol(result[0][0].second);
    long edgeCount = stol(result[0][1].second);
    
    memoryPartitioner_logger.log("Graph " + graphId + " - Vertices: " + to_string(vertexCount) + 
                               ", Edges: " + to_string(edgeCount), "info");
    
    return calculateGraphSizeFromCounts(vertexCount, edgeCount);
}

long MemoryBasedPartitioner::getWorkerTotalMemory(const string& hostname) {
    string perfSqlStatement = 
        "SELECT memory_usage FROM host_performance_data INNER JOIN (SELECT idhost FROM host WHERE ip = '" + 
        hostname + "') USING (idhost) ORDER BY date_time DESC LIMIT 1";
    
    vector<vector<pair<string, string>>> result = performanceDb->runSelect(perfSqlStatement);
    
    if (result.empty()) {
        memoryPartitioner_logger.log("No performance data found for host " + hostname, "warn");
        return 0;
    }
    
    return stol(result[0][0].second); // Returns memory in KB
}

int MemoryBasedPartitioner::getWorkerCoreCount(const string& hostname) {
    // For now, we'll use the hardware_concurrency as an approximation
    // In a real distributed environment, this would need to query each worker
    // or maintain core count information in the database
    
    // Try to get from performance data or use a default based on typical server configurations
    // This is a simplified implementation - in production, you'd want to store and retrieve
    // actual core counts from worker nodes
    
    string sqlStatement = "SELECT server_data_port FROM worker WHERE ip = '" + hostname + "' LIMIT 1";
    vector<vector<pair<string, string>>> result = sqlite->runSelect(sqlStatement);
    
    if (result.empty()) {
        return 0;
    }
    
    // For demonstration, assume typical server has 4-8 cores
    // In real implementation, this should be queried from actual worker nodes
    return 4; // Default assumption
}

vector<string> MemoryBasedPartitioner::getActiveWorkers() {
    vector<string> workers;
    
    string sqlStatement = "SELECT DISTINCT ip FROM worker";
    vector<vector<pair<string, string>>> result = sqlite->runSelect(sqlStatement);
    
    for (const auto& row : result) {
        workers.push_back(row[0].second);
    }
    
    memoryPartitioner_logger.log("Found " + to_string(workers.size()) + " active workers", "info");
    
    return workers;
}

long MemoryBasedPartitioner::calculateGraphSizeFromCounts(long vertexCount, long edgeCount) {
    // Use the GraphSizeEstimator utility for consistent estimation
    return GraphSizeEstimator::estimateFromCounts(vertexCount, edgeCount);
}