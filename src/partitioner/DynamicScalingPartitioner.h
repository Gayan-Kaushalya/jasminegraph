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

#ifndef JASMINEGRAPH_DYNAMIC_SCALING_PARTITIONER_H
#define JASMINEGRAPH_DYNAMIC_SCALING_PARTITIONER_H

#include "GraphEdgeOrderer.h"
#include "ChunkBasedPartitioner.h"
#include "stream/Partition.h"
#include <vector>
#include <unordered_map>
#include <memory>

using Graph = std::unordered_map<std::string, std::vector<std::string>>;

class DynamicScalingPartitioner {
public:
    /**
     * Constructor.
     * @param graph Adjacency list of the graph.
     * @param k_min Minimum partitions.
     * @param k_max Maximum partitions.
     */
    DynamicScalingPartitioner(const Graph& graph, int k_min = 4, int k_max = 128);

    /**
     * Partitions the graph into k partitions.
     * @param k Number of partitions.
     * @return Vector of Partition objects.
     */
    std::vector<std::unique_ptr<Partition>> partition(int k);

    /**
     * Repartitions from current k to new_k efficiently.
     * @param new_k New number of partitions.
     * @return New vector of Partition objects.
     */
    std::vector<std::unique_ptr<Partition>> repartition(int new_k);

private:
    Graph graph_;
    std::vector<Edge> ordered_edges_;
    int current_k_;
    int k_min_;
    int k_max_;
    GraphEdgeOrderer orderer_;
    ChunkBasedPartitioner chunk_partitioner_;
};

#endif  // JASMINEGRAPH_DYNAMIC_SCALING_PARTITIONER_H
