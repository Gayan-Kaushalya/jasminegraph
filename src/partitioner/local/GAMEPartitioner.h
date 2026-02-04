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

#ifndef JASMINEGRAPH_GAMEPARTITIONER_H
#define JASMINEGRAPH_GAMEPARTITIONER_H

#include <string>
#include <map>
#include <vector>
#include "../../metadb/SQLiteDBInterface.h"

using std::string;
using std::map;
using std::vector;

/**
 * GAMEPartitioner provides integration with the GAME (Graph partitioning 
 * using Adaptive Multi-agent Evolution) framework, a streaming graph
 * partitioning approach based on Stackelberg game theory.
 */
class GAMEPartitioner {
private:
    SQLiteDBInterface *sqlite;
    int lastGraphID;
    string lastMethod;
    map<string, string> lastStats;

public:
    /**
     * Constructor
     * @param sqlite Database interface for partition metadata storage
     */
    explicit GAMEPartitioner(SQLiteDBInterface *sqlite);

    /**
     * Partition a graph using GAME algorithm
     * @param inputFilePath Path to input graph file (edge list format)
     * @param graphID Graph identifier
     * @param partitionCount Number of partitions to create
     * @param alpha Balance parameter (default: 1.0)
     * @param beta Replication parameter (default: 1.0) 
     * @param k Number of clusters (default: 100)
     * @return Map of partition ID to partition file path
     */
    map<int, string> partition(
        const string& inputFilePath,
        int graphID,
        int partitionCount,
        double alpha = 1.0,
        double beta = 1.0,
        int k = 100
    );

    /**
     * Get statistics from last partitioning operation
     * @return Map of statistic names to values
     */
    map<string, string> getPartitionStats();

private:
    /**
     * Create partition file map for output files
     * @param outputDir Output directory path
     * @param graphID Graph identifier
     * @param partitionCount Number of partitions
     * @return Map of partition ID to file path
     */
    map<int, string> createPartitionFileMap(
        const string& outputDir,
        int graphID,
        int partitionCount
    );

    /**
     * Count vertices and edges in graph file
     * @param inputFilePath Input graph file
     * @param vCount Output vertex count
     * @param eCount Output edge count
     */
    void countGraphSize(const string& inputFilePath, int& vCount, int& eCount);
};

#endif // JASMINEGRAPH_GAMEPARTITIONER_H
