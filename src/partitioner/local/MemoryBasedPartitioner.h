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

#ifndef JASMINEGRAPH_MEMORYBASEDPARTITIONER_H
#define JASMINEGRAPH_MEMORYBASEDPARTITIONER_H

#include <string>
#include <map>
#include <vector>

#include "../../metadb/SQLiteDBInterface.h"
#include "../../performancedb/PerformanceSQLiteDBInterface.h"

using namespace std;

/**
 * Memory-based graph partitioner that calculates the number of partitions
 * based on available memory per CPU core across worker processes.
 */
class MemoryBasedPartitioner {
public:
    explicit MemoryBasedPartitioner(SQLiteDBInterface *sqlite);
    
    /**
     * Calculate the number of partitions needed based on memory constraints
     * @param graphId The ID of the graph to partition
     * @param graphSize The size of the input graph in bytes
     * @return The calculated number of partitions
     */
    int calculatePartitionCount(const string& graphId, long graphSize);
    
    /**
     * Get the memory allocated to a single logical CPU core for each worker
     * @return Map of worker hostname to memory per core in bytes
     */
    map<string, long> getWorkerMemoryPerCore();
    
    /**
     * Find the minimum memory value across all worker cores
     * @param workerMemoryMap Map of worker to memory per core
     * @return Minimum memory value in bytes
     */
    long getMinimumWorkerMemory(const map<string, long>& workerMemoryMap);
    
    /**
     * Estimate the memory size of the input graph
     * @param graphId The ID of the graph
     * @return Graph memory size in bytes
     */
    long estimateGraphMemorySize(const string& graphId);
    
private:
    SQLiteDBInterface *sqlite;
    PerformanceSQLiteDBInterface *performanceDb;
    
    /**
     * Get total memory for a worker host
     * @param hostname The hostname of the worker
     * @return Total memory in KB
     */
    long getWorkerTotalMemory(const string& hostname);
    
    /**
     * Get number of CPU cores for a worker host
     * @param hostname The hostname of the worker
     * @return Number of CPU cores
     */
    int getWorkerCoreCount(const string& hostname);
    
    /**
     * Get active workers from database
     * @return Vector of worker hostnames
     */
    vector<string> getActiveWorkers();
    
    /**
     * Calculate graph size based on vertex and edge counts
     * @param vertexCount Number of vertices
     * @param edgeCount Number of edges
     * @return Estimated graph size in bytes
     */
    long calculateGraphSizeFromCounts(long vertexCount, long edgeCount);
};

#endif //JASMINEGRAPH_MEMORYBASEDPARTITIONER_H