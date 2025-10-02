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

#include "GraphEdgeOrderer.h"
#include <algorithm>
#include <queue>
#include <stdexcept>
#include <cmath>  // for floor

std::vector<Edge> GraphEdgeOrderer::orderEdges(const Graph& graph, int k_min, int k_max) {
    // Compute total number of edges (undirected, so |E| = sum degrees / 2)
    size_t total_edges = 0;
    for (const auto& pair : graph) {
        total_edges += pair.second.size();
    }
    total_edges /= 2;  // Undirected graph
    num_edges = total_edges;

    computePriorityParams(num_edges, k_min, k_max);
    return greedyOrderEdges(graph, k_min, k_max);
}

void GraphEdgeOrderer::computePriorityParams(size_t num_edges, int k_min, int k_max) {
    this->num_edges = num_edges;
    alpha = 0.0;
    for (int k = k_min; k <= k_max; ++k) {
        alpha += std::floor(static_cast<double>(num_edges) / k);
    }
    beta = static_cast<double>(k_max - k_min);
}

std::vector<Edge> GraphEdgeOrderer::greedyOrderEdges(const Graph& graph, int k_min, int k_max) {
    std::vector<Edge> ordered_edges;
    std::unordered_map<std::string, int> remaining_degree;  // D[v]
    std::unordered_map<std::string, size_t> last_order;     // M[v]
    std::unordered_set<std::string> remaining_vertices;

    // Initialize degrees and remaining vertices
    for (const auto& pair : graph) {
        const std::string& v = pair.first;
        remaining_degree[v] = graph.at(v).size();
        last_order[v] = 0;  // Initial M[v] = 0
        remaining_vertices.insert(v);
    }

    // Priority queue: min-heap for smallest p(v)
    auto comparator = [this](const VertexPriority& a, const VertexPriority& b) {
        double pa = alpha * a.degree - beta * a.last_order;
        double pb = alpha * b.degree - beta * b.last_order;
        return pa > pb;  // Greater for min-heap (smallest p first)
    };
    std::priority_queue<VertexPriority, std::vector<VertexPriority>, decltype(comparator)> pq(comparator);

    size_t current_order = 0;
    std::unordered_set<std::string> ordered_vertices;
    std::unordered_set<Edge, hash_edge> ordered_edge_set;  // To avoid duplicates in undirected graph

    // Select initial random vertex if PQ empty
    if (!remaining_vertices.empty()) {
        auto it = remaining_vertices.begin();
        std::advance(it, std::rand() % remaining_vertices.size());  // Simple random selection
        std::string v_min = *it;
        ordered_vertices.insert(v_min);
        remaining_vertices.erase(v_min);

        // Order one-hop neighbors (edges from v_min)
        for (const std::string& u : getNeighbors(graph, v_min)) {
            Edge e = {v_min, u};
            if (e.first > e.second) std::swap(e.first, e.second);  // Canonical order for undirected
            if (ordered_edge_set.find(e) == ordered_edge_set.end()) {
                ordered_edges.push_back(e);
                ordered_edge_set.insert(e);
                last_order[v_min] = current_order++;
                last_order[u] = current_order;
                remaining_degree[v_min]--;
                remaining_degree[u]--;
            }
        }

        // Enqueue updated neighbors for PQ
        for (const std::string& u : getNeighbors(graph, v_min)) {
            if (remaining_vertices.count(u)) {
                pq.push(VertexPriority(remaining_degree[u], last_order[u], u));
            }
        }
    }

    size_t delta = getDelta(k_max);

    // Greedy expansion loop
    while (!remaining_vertices.empty() && !pq.empty()) {
        VertexPriority v_prio = pq.top();
        pq.pop();
        std::string v_min = v_prio.vertex_id;

        if (ordered_vertices.count(v_min) || remaining_degree[v_min] == 0) continue;

        ordered_vertices.insert(v_min);
        remaining_vertices.erase(v_min);

        // Order one-hop neighbors (remaining edges from v_min)
        for (const std::string& u : getNeighbors(graph, v_min)) {
            Edge e = {v_min, u};
            if (e.first > e.second) std::swap(e.first, e.second);
            if (ordered_edge_set.find(e) == ordered_edge_set.end() && remaining_degree[v_min] > 0) {
                ordered_edges.push_back(e);
                ordered_edge_set.insert(e);
                last_order[v_min] = current_order;
                last_order[u] = current_order++;
                remaining_degree[v_min]--;
                remaining_degree[u]--;
            }
        }

        // Order two-hop neighbors within delta
        for (const std::string& u : getNeighbors(graph, v_min)) {
            if (remaining_degree[u] == 0) continue;
            bool within_delta = (current_order - last_order[u]) <= delta;
            if (within_delta) {
                for (const std::string& w : getNeighbors(graph, u)) {
                    if (w == v_min) continue;
                    Edge e = {u, w};
                    if (e.first > e.second) std::swap(e.first, e.second);
                    if (ordered_edge_set.find(e) == ordered_edge_set.end() && remaining_degree[u] > 0) {
                        ordered_edges.push_back(e);
                        ordered_edge_set.insert(e);
                        last_order[u] = current_order;
                        last_order[w] = current_order++;
                        remaining_degree[u]--;
                        remaining_degree[w]--;
                    }
                }
            }
        }

        // Update PQ for affected vertices
        for (const std::string& affected : ordered_vertices) {  // Simplified; in practice, track frontier
            if (remaining_vertices.count(affected) && remaining_degree[affected] > 0) {
                pq.push(VertexPriority(remaining_degree[affected], last_order[affected], affected));
            }
        }
    }

    // If any edges left (disconnected components), add them arbitrarily
    for (const auto& pair : graph) {
        const std::string& v = pair.first;
        if (remaining_degree[v] > 0) {
            for (const std::string& u : getNeighbors(graph, v)) {
                Edge e = {v, u};
                if (e.first > e.second) std::swap(e.first, e.second);
                if (ordered_edge_set.find(e) == ordered_edge_set.end()) {
                    ordered_edges.push_back(e);
                    ordered_edge_set.insert(e);
                }
            }
        }
    }

    return ordered_edges;
}

std::vector<std::string> GraphEdgeOrderer::getNeighbors(const Graph& graph, const std::string& v) {
    auto it = graph.find(v);
    if (it != graph.end()) {
        return it->second;
    }
    return {};
}

size_t GraphEdgeOrderer::getDelta(int k_max) {
    return std::floor(static_cast<double>(num_edges) / k_max);
}
