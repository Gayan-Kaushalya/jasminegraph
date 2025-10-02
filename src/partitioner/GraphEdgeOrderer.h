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

#ifndef JASMINEGRAPH_GRAPH_EDGE_ORDERER_H
#define JASMINEGRAPH_GRAPH_EDGE_ORDERER_H

#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <utility>  // for std::pair
#include <functional>  // for std::hash

// Representation of an edge as pair of vertex IDs (strings, as per JasmineGraph)
using Edge = std::pair<std::string, std::string>;
using Graph = std::unordered_map<std::string, std::vector<std::string>>;  // Adjacency list

// Hash function for Edge
struct hash_edge {
    size_t operator()(const Edge& e) const {
        return std::hash<std::string>()(e.first) ^ std::hash<std::string>()(e.second);
    }
};

class GraphEdgeOrderer {
public:
    /**
     * Orders the edges of the graph using the greedy algorithm from the paper.
     * @param graph Adjacency list representation of the graph.
     * @param k_min Minimum number of partitions (default 4).
     * @param k_max Maximum number of partitions (default 128).
     * @return Ordered list of edges (as vector of Edge pairs).
     */
    std::vector<Edge> orderEdges(const Graph& graph, int k_min = 4, int k_max = 128);

    /**
     * Computes parameters alpha and beta for priority queue.
     */
    void computePriorityParams(size_t num_edges, int k_min, int k_max);

private:
    double alpha;
    double beta;
    size_t num_edges;

    /**
     * Struct for vertex priority in priority queue.
     */
    struct VertexPriority {
        int degree;  // D[v]: remaining degree
        size_t last_order;  // M[v]: last edge order involving v
        std::string vertex_id;

        VertexPriority(int d, size_t m, std::string id) : degree(d), last_order(m), vertex_id(id) {}
    };

    /**
     * Greedy expansion algorithm (Algorithm 4 equivalent).
     */
    std::vector<Edge> greedyOrderEdges(const Graph& graph, int k_min, int k_max);

    /**
     * Get neighbors of a vertex.
     */
    std::vector<std::string> getNeighbors(const Graph& graph, const std::string& v);

    /**
     * Delta for two-hop neighbors (smallest chunk size).
     */
    size_t getDelta(int k_max);
};

#endif  // JASMINEGRAPH_GRAPH_EDGE_ORDERER_H
