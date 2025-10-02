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

#ifndef JASMINEGRAPH_CHUNK_BASED_PARTITIONER_H
#define JASMINEGRAPH_CHUNK_BASED_PARTITIONER_H

#include <vector>
#include <string>
#include <utility>  // for std::pair

// Representation of an edge as pair of vertex IDs (strings, as per JasmineGraph)
using Edge = std::pair<std::string, std::string>;

class ChunkBasedPartitioner {
public:
    /**
     * Partitions the ordered edges into k partitions using chunk-based splitting.
     * @param ordered_edges Ordered list of edges from GraphEdgeOrderer.
     * @param k Number of partitions.
     * @return Vector of vectors: each inner vector is a partition of edges.
     */
    std::vector<std::vector<Edge>> partitionEdges(const std::vector<Edge>& ordered_edges, int k);

private:
    /**
     * Computes the size of each chunk for k partitions.
     * @param total_edges Total number of edges.
     * @param k Number of partitions.
     * @return Vector of chunk sizes.
     */
    std::vector<size_t> computeChunkSizes(size_t total_edges, int k);
};

#endif  // JASMINEGRAPH_CHUNK_BASED_PARTITIONER_H
