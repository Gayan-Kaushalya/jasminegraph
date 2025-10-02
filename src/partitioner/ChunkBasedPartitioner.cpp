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

#include "ChunkBasedPartitioner.h"
#include <cmath>  // for floor

std::vector<std::vector<Edge>> ChunkBasedPartitioner::partitionEdges(const std::vector<Edge>& ordered_edges, int k) {
    size_t total_edges = ordered_edges.size();
    std::vector<size_t> chunk_sizes = computeChunkSizes(total_edges, k);
    std::vector<std::vector<Edge>> partitions(k);

    size_t edge_index = 0;
    for (int i = 0; i < k; ++i) {
        size_t chunk_size = chunk_sizes[i];
        for (size_t j = 0; j < chunk_size; ++j) {
            if (edge_index < total_edges) {
                partitions[i].push_back(ordered_edges[edge_index++]);
            }
        }
    }

    return partitions;
}

std::vector<size_t> ChunkBasedPartitioner::computeChunkSizes(size_t total_edges, int k) {
    std::vector<size_t> sizes(k);
    size_t base_size = total_edges / k;
    size_t remainder = total_edges % k;

    for (int i = 0; i < k; ++i) {
        sizes[i] = base_size + (i < remainder ? 1 : 0);
    }

    return sizes;
}
