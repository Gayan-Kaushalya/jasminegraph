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

#include "DynamicScalingPartitioner.h"
#include "stream/Partition.h"
#include <algorithm>
#include <memory>

DynamicScalingPartitioner::DynamicScalingPartitioner(const Graph& graph, int k_min, int k_max)
    : graph_(graph), k_min_(k_min), k_max_(k_max), current_k_(0), orderer_(), chunk_partitioner_() {
    // Order edges once during construction
    ordered_edges_ = orderer_.orderEdges(graph_, k_min_, k_max_);
}

std::vector<std::unique_ptr<Partition>> DynamicScalingPartitioner::partition(int k) {
    if (k < k_min_ || k > k_max_) {
        throw std::invalid_argument("k must be between k_min and k_max");
    }

    auto edge_partitions = chunk_partitioner_.partitionEdges(ordered_edges_, k);

    std::vector<std::unique_ptr<Partition>> partitions;
    for (int i = 0; i < k; ++i) {
        auto partition = std::make_unique<Partition>(i, k);
        for (const auto& edge : edge_partitions[i]) {
            partition->addEdge(edge, false);  // Assume undirected for now
        }
        partitions.push_back(std::move(partition));
    }

    current_k_ = k;
    return partitions;
}

std::vector<std::unique_ptr<Partition>> DynamicScalingPartitioner::repartition(int new_k) {
    if (new_k < k_min_ || new_k > k_max_) {
        throw std::invalid_argument("new_k must be between k_min and k_max");
    }

    // For simplicity, re-partition from ordered edges (O(1) chunking ensures efficiency)
    // In full implementation, split/merge chunks without re-ordering for true O(1)
    return partition(new_k);
}
