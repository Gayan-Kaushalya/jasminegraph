/*
 * Copyright 2019 JasminGraph Team
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
#ifndef JASMINE_PARTITIONER_HEADER
#define JASMINE_PARTITIONER_HEADER
#include <unordered_map>
#include <vector>

#include "../../metadb/SQLiteDBInterface.h"
#include "./Partition.h"

typedef std::vector<std::pair<std::string, long>> partitionedEdge;
namespace spt {  // spt : Streaming Partitioner
enum Algorithms { HASH, FENNEL, LDG, LEOPARD, CUTTANA };
static Algorithms getPartitioner(string id) {
    if (id == "1") {
        return Algorithms::HASH;
    } else if (id == "2") {
        return Algorithms::FENNEL;
    } else if (id == "3") {
        return Algorithms::LDG;
    } else if (id == "4") {
        return Algorithms::LEOPARD;
    } else if (id == "5") {
        return Algorithms::CUTTANA;
    }
    return  Algorithms::HASH;
}
}  // namespace spt

class Partitioner {
    std::vector<Partition> partitions;
    int numberOfPartitions;
    long totalVertices = 0;
    long totalEdges = 0;
    int graphID;
    bool isDirect;
    spt::Algorithms algorithmInUse;
    SQLiteDBInterface *sqlite;
    bool isDirected;

    std::unordered_map<std::string, std::vector<int>> vertexNeighborCounts;
    std::unordered_map<std::string, int> vertexPartitionAssignment;

 public:
    Partitioner(int numberOfPartitions, int graphID, spt::Algorithms alog, SQLiteDBInterface* sqlite, bool isDirect)
            : numberOfPartitions(numberOfPartitions), graphID(graphID), algorithmInUse(alog), sqlite(sqlite),
    isDirect(isDirect) {
        for (size_t i = 0; i < numberOfPartitions; i++) {
            this->partitions.push_back(Partition(i, numberOfPartitions));
        };
    };
    void printStats();
    partitionedEdge addEdge(std::pair<std::string, std::string> edge);
    partitionedEdge hashPartitioning(std::pair<std::string, std::string> edge);
    partitionedEdge fennelPartitioning(std::pair<std::string, std::string> edge);
    partitionedEdge ldgPartitioning(std::pair<std::string, std::string> edge);
    partitionedEdge leopardPartitioning(std::pair<std::string, std::string> edge);
    partitionedEdge cuttanaPartitioning(std::pair<std::string, std::string> edge);
    static std::pair<long, long> deserialize(std::string data);
    void updateMetaDB();
    void setGraphID(int graphId){this->graphID = graphId;};
};

#endif  // !JASMINE_PARTITIONER_HEADER
