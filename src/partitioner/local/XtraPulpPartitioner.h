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

#ifndef JASMINEGRAPH_XTRAPULPPARTITIONER_H
#define JASMINEGRAPH_XTRAPULPPARTITIONER_H

#include <string>
#include <vector>
#include <map>
#include "../../metadb/SQLiteDBInterface.h"

/**
 * Wrapper class for XtraPuLP graph partitioning
 * This class provides integration with the XtraPuLP partitioner
 * without modifying existing native store and localstores
 */
class XtraPulpPartitioner {
 public:
    XtraPulpPartitioner(SQLiteDBInterface *db);
    
    /**
     * Partition a graph using XtraPuLP algorithm
     * @param graphID The graph ID in the database
     * @param inputFilePath Path to the input graph file (edge list format)
     * @param numPartitions Number of partitions to create
     * @param vertexBalance Vertex balance constraint (default: 1.10 for 10%)
     * @param edgeBalance Edge balance constraint (0 = off)
     * @return Map of partition ID to partition file paths
     */
    std::vector<std::map<int, std::string>> partitionWithXtraPulp(
        int graphID,
        const std::string& inputFilePath,
        int numPartitions,
        double vertexBalance = 1.10,
        double edgeBalance = 0.0
    );
    
    /**
     * Check if XtraPuLP is available and properly configured
     * @return true if XtraPuLP can be used
     */
    bool isAvailable();
    
 private:
    SQLiteDBInterface *sqlite;
    
    /**
     * Convert graph file to format suitable for XtraPuLP if needed
     * @param inputPath Input graph file path
     * @param outputPath Output file path for converted graph
     * @return true if conversion successful
     */
    bool convertToXtraPulpFormat(const std::string& inputPath, const std::string& outputPath);
    
    /**
     * Read partition results and create partition files
     * @param graphID The graph ID
     * @param partitionFile XtraPuLP output partition file
     * @param numPartitions Number of partitions
     * @return Map of partition files
     */
    std::vector<std::map<int, std::string>> createPartitionFiles(
        int graphID,
        const std::string& partitionFile,
        int numPartitions
    );
};

#endif  // JASMINEGRAPH_XTRAPULPPARTITIONER_H
