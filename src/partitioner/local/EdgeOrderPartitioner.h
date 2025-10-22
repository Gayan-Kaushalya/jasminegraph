/**
 * Copyright 2024 JasmineGraph Team
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef JASMINEGRAPH_EDGEORDERPARTITIONER_H
#define JASMINEGRAPH_EDGEORDERPARTITIONER_H

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <mutex>

#include "../../metadb/SQLiteDBInterface.h"

using std::string;

typedef int32_t idx_t;

/**
 * EdgeOrderPartitioner - A simple partitioner that orders graph edges
 * and chunks them based on worker count. Replaces METIS partitioning.
 */
class EdgeOrderPartitioner {
 public:
    EdgeOrderPartitioner(SQLiteDBInterface *sqlite);

    /**
     * Load graph dataset from file
     * @param inputFilePath Path to edge list file
     * @param graphID ID of the graph
     */
    void loadDataSet(string inputFilePath, int graphID);

    /**
     * Partition the graph based on worker count
     * @param workerCount Number of workers/partitions
     * @return List of file maps for partition files
     */
    std::vector<std::map<int, std::string>> partition(int workerCount);

    /**
     * Reformat dataset with sequential vertex IDs
     * @param inputFilePath Path to input file
     * @param graphID ID of the graph
     * @return Path to reformatted file
     */
    std::string reformatDataSet(string inputFilePath, int graphID);

    /**
     * Load content/attribute data
     * @param inputAttributeFilePath Path to attribute file
     * @param graphAttributeType Type of attributes
     * @param graphID ID of the graph
     * @param attrType Attribute type
     */
    void loadContentData(string inputAttributeFilePath, string graphAttributeType, 
                        int graphID, string attrType = "");

 private:
    SQLiteDBInterface *sqlite;
    int graphID;
    int nParts;
    idx_t edgeCount;
    idx_t vertexCount;
    idx_t largestVertex;
    int smallestVertex;
    bool zeroflag;
    string outputFilePath;
    string graphType;
    string graphAttributeType;

    // Graph data structures
    std::map<int, std::vector<int>> graphStorageMap;  // Adjacency list (deduplicated)
    std::map<int, std::vector<int>> graphEdgeMap;     // All edges with duplicates
    std::vector<std::pair<int, int>> orderedEdges;    // Ordered edge list
    
    std::map<int, int> vertexToIDMap;
    std::map<int, int> idToVertexMap;
    std::map<int, std::string> attributeDataMap;
    std::map<long, string[7]> articlesMap;

    // Partition data structures
    std::unordered_map<int, size_t> partVertexCounts;
    std::unordered_map<int, size_t> masterEdgeCounts;
    std::unordered_map<int, size_t> masterEdgeCountsWithDups;
    std::map<int, std::map<int, std::vector<int>>> partitionedLocalGraphStorageMap;
    std::map<int, std::map<int, std::vector<int>>> masterGraphStorageMap;
    std::map<int, std::map<int, std::vector<int>>> duplicateMasterGraphStorageMap;
    std::map<int, std::map<int, std::map<int, std::vector<int>>>> commonCentralStoreEdgeMap;
    
    std::map<int, std::string> partitionFileMap;
    std::map<int, std::string> centralStoreFileList;
    std::map<int, std::string> compositeCentralStoreFileList;
    std::map<int, std::string> centralStoreDuplicateFileList;
    std::map<int, std::string> partitionAttributeFileList;
    std::map<int, std::string> centralStoreAttributeFileList;
    std::vector<std::map<int, std::string>> fullFileList;

    // Helper methods
    void orderEdges();
    std::map<int, int> chunkEdgesToPartitions();
    void createPartitionFiles(std::map<int, int> partMap);
    void populatePartMaps(std::map<int, int> partMap, int part);
    
    void writeSerializedPartitionFiles(int part);
    void writeSerializedMasterFiles(int part);
    void writeSerializedDuplicateMasterFiles(int part);
    void writeSerializedCompositeMasterFiles(std::string part);
    void writeTextAttributeFilesForPartitions(int part);
    void writeTextAttributeFilesForMasterParts(int part);
    void writeRDFAttributeFilesForPartitions(int part);
    void writeRDFAttributeFilesForMasterParts(int part);
};

#endif  // JASMINEGRAPH_EDGEORDERPARTITIONER_H
