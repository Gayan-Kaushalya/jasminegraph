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

#ifndef JASMINEGRAPH_DNEPARTITIONER_H
#define JASMINEGRAPH_DNEPARTITIONER_H

#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <queue>
#include <cstdint>

#include "../../metadb/SQLiteDBInterface.h"

using vertex_id = int;
using partition_id = int;

/**
 * DNEPartitioner - Distributed Neighbor Expansion edge partitioner
 * 
 * Adapted from the DistributedNE project (Masatoshi Hanai, 2019).
 * This implementation removes the MPI dependency and runs the NE 
 * algorithm in a single process, partitioning edges into balanced
 * partitions while minimizing vertex replication.
 *
 * Algorithm overview:
 *   1. Initial assignment: edges are assigned to partitions using a 2D-hash
 *      of their source and destination vertex IDs.
 *   2. Iterative boundary expansion: vertices on partition boundaries are 
 *      expanded into neighboring partitions to improve locality, scored by
 *      the number of unallocated incident edges.
 *   3. Termination: expansion stops when all edges are assigned or the
 *      balance constraint is violated.
 *
 * The result is an edge partition (not vertex partition), where each edge
 * is assigned to exactly one partition. Vertices may appear in multiple
 * partitions (replicas).
 */
class DNEPartitioner {
 public:
    explicit DNEPartitioner(SQLiteDBInterface *sqlite);

    /**
     * Partition a graph and return file lists for worker distribution.
     * 
     * @param graphID    Database ID for this graph
     * @param graphPath  Path to edge-list file (whitespace-separated src dst per line)
     * @param outputPath Base output path (e.g. "/data/1_")
     * @param numPartitions Number of partitions to create
     * @return Vector of maps: [localFiles, centralFiles, duplicateCentralFiles, 
     *         emptyAttrs, emptyCentralAttrs, emptyComposite]
     *         Empty vector on failure.
     */
    std::vector<std::map<int, std::string>> partitionGraph(
        int graphID, const std::string &graphPath,
        const std::string &outputPath, int numPartitions);

 private:
    SQLiteDBInterface *sqlite;
    int numPartitions;
    
    // Graph data
    std::unordered_map<vertex_id, std::vector<vertex_id>> adjacencyList;
    size_t totalEdges;

    // Edge partition assignment: adjList edges indexed by (source, neighbor_index) -> partition
    // For each edge (u, v), edgePartition stores which partition it belongs to
    std::map<std::pair<vertex_id, vertex_id>, partition_id> edgePartition;

    // Per-partition edge counts (directed edges assigned)
    std::vector<size_t> partitionEdgeCounts;
    
    // Vertex scores: number of unallocated incident edges
    std::unordered_map<vertex_id, size_t> vertexScore;

    // Boundary queue: vertices sorted by score (ascending) for expansion
    // pair<score, vertex_id>
    struct BoundaryEntry {
        size_t score;
        vertex_id vertex;
        partition_id partition;
        bool operator>(const BoundaryEntry &other) const {
            return score > other.score;  // min-heap by score
        }
    };

    // Output file maps
    std::map<int, std::string> partitionFileMap;
    std::map<int, std::string> centralStoreFileList;
    std::map<int, std::string> centralStoreDuplicateFileList;
    std::vector<std::map<int, std::string>> fullFileList;

    // Partition statistics
    std::vector<size_t> partitionVertexCounts;
    std::vector<size_t> partitionEdgeCountsVec;
    size_t edgeCuts;

    // Algorithm parameters
    double expandRatio;
    double balanceFactor;

    // Methods
    bool loadGraph(const std::string &graphPath);
    void assignPartitions();
    bool writePartitions(const std::string &outputPath);
    void calculateEdgeCuts();

    /**
     * 2D-hash initial assignment: assigns an edge to the partition
     * computed from hash(src, dst) % numPartitions.
     */
    partition_id hashAssign(vertex_id src, vertex_id dst) const;

    /**
     * Expand a vertex into a partition: assign all unallocated edges
     * incident to this vertex to the given partition.
     */
    void expandVertex(vertex_id v, partition_id p);
};

#endif  // JASMINEGRAPH_DNEPARTITIONER_H
