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

#ifndef JASMINEGRAPH_LABELPROPAGATIONPARTITIONER_H
#define JASMINEGRAPH_LABELPROPAGATIONPARTITIONER_H

#include <string>
#include <map>
#include <unordered_map>
#include <vector>
#include <set>

#include "../../metadb/SQLiteDBInterface.h"

using std::string;

class LabelPropagationPartitioner {
 private:
    SQLiteDBInterface *sqlite;
    int graphID;
    string inputFilePath;
    string outputFilePath;
    int maxIterations;
    
    // Graph structure
    std::unordered_map<int, std::vector<int>> adjacencyList;
    std::unordered_map<int, int> nodeLabels;
    std::set<int> uniqueLabels;
    int vertexCount;
    int edgeCount;
    bool zeroflag;
    
    // Helper methods
    void loadGraph();
    void initializeLabels();
    void propagateLabels();
    int getMostFrequentLabel(int nodeId);
    void writePartitions();

 public:
    LabelPropagationPartitioner(SQLiteDBInterface *sqlite);
    void loadDataSet(string inputFilePath, int graphID);
    std::vector<std::map<int, std::string>> partition();
    int getPartitionCount();
};

#endif  // JASMINEGRAPH_LABELPROPAGATIONPARTITIONER_H
