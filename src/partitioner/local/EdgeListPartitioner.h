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

#ifndef JASMINEGRAPH_EDGELISTPARTITIONER_H
#define JASMINEGRAPH_EDGELISTPARTITIONER_H

#include <algorithm>
#include <cstddef>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../../centralstore/JasmineGraphHashMapCentralStore.h"
#include "../../localstore/JasmineGraphHashMapLocalStore.h"
#include "../../metadb/SQLiteDBInterface.h"
#include "../../util/Utils.h"

using std::string;

class EdgeListPartitioner {
 public:
    void loadDataSet(string inputFilePath, int graphID);

    // Partition graph by chunking edges ordered by source vertex
    std::vector<std::map<int, std::string>> partitionByEdgeList(string partitionCount);

    // Reformat the vertex list by mapping vertex values to new sequential IDs
    std::string reformatDataSet(string inputFilePath, int graphID);

    void loadContentData(string inputAttributeFilePath, string graphAttributeType, int graphID, string attrType);

    EdgeListPartitioner(SQLiteDBInterface *);

 private:
    long edgeCount = 0;
    int vertexCount = 0;
    int nParts = 0;
    string outputFilePath;
    bool zeroflag = false;
    SQLiteDBInterface *sqlite;
    int graphID;
    string graphType;
    int smallestVertex = std::numeric_limits<int>::max();
    int largestVertex = 0;
    string graphAttributeType;

    std::map<int, std::string> partitionFileMap;
    std::map<int, std::string> centralStoreFileList;
    std::map<int, std::string> compositeCentralStoreFileList;
    std::map<int, std::string> centralStoreDuplicateFileList;
    std::map<int, std::string> partitionAttributeFileList;
    std::map<int, std::string> centralStoreAttributeFileList;
    std::vector<std::map<int, std::string>> fullFileList;

    // Store edges as a vector to maintain order
    std::vector<std::pair<int, int>> edgeList;
    std::unordered_map<int, std::unordered_set<int>> vertexEdges;
    std::map<int, std::map<int, std::vector<int>>> partitionedLocalGraphStorageMap;
    std::map<int, std::map<int, std::vector<int>>> masterGraphStorageMap;
    std::map<std::string, std::map<int, std::vector<int>>> compositeMasterGraphStorageMap;
    std::map<int, std::map<int, std::vector<int>>> duplicateMasterGraphStorageMap;
    std::unordered_map<int, size_t> partVertexCounts;
    std::unordered_map<int, size_t> masterEdgeCounts;
    std::unordered_map<int, size_t> masterEdgeCountsWithDups;

    std::map<int, int> vertexToIDMap;
    std::map<int, int> idToVertexMap;
    std::map<int, std::string> attributeDataMap;
    std::map<std::pair<int, int>, int> edgeMap;
    std::map<long, string[7]> articlesMap;

    void createPartitionFiles(std::map<int, int> partMap);
    void populatePartMaps(std::map<int, int> partMap, int part);
    void writeSerializedMasterFiles(int part);
    void writeSerializedCompositeMasterFiles(std::string part);
    void writeSerializedDuplicateMasterFiles(int part);
    void writeSerializedPartitionFiles(int part);
    void writeRDFAttributeFilesForPartitions(int part);
    void writeRDFAttributeFilesForMasterParts(int part);
    void writeTextAttributeFilesForPartitions(int part);
    void writeTextAttributeFilesForMasterParts(int part);
};

#endif  // JASMINEGRAPH_EDGELISTPARTITIONER_H
