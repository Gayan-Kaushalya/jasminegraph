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

#include "Partitioner.h"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <vector>
#include <ctime>
#include <chrono>

#include "../../util/logger/Logger.h"
#include "../../util/Conts.h"
#include <nlohmann/json.hpp>
using namespace nlohmann;
Logger streaming_partitioner_logger;

partitionedEdge Partitioner::addEdge(std::pair<std::string, std::string> edge) {
    switch (this->algorithmInUse) {
        case spt::Algorithms::HASH:
            return this->hashPartitioning(edge);
            break;
        case spt::Algorithms::FENNEL:
            return this->fennelPartitioning(edge);
            break;
        case spt::Algorithms::LDG:
            return this->ldgPartitioning(edge);
            break;
        case spt::Algorithms::LEOPARD:
            return this->leopardPartitioning(edge);
            break;
        case spt::Algorithms::CUTTANA:
            return this->cuttanaPartitioning(edge);
            break;
        default:
            break;
    }
    return this->hashPartitioning(edge);
}
/**
 * Linear deterministic greedy algorithem by Stanton and Kilot et al
 * equation for greedy assignment |N(v) ∩ Si| x (1 - |Si|/(n/k) )
 *
 * **/
partitionedEdge Partitioner::ldgPartitioning(std::pair<std::string, std::string> edge) {
    std::vector<double> partitionScoresFirst(numberOfPartitions, 0);   // Calculate per incoming edge
    std::vector<double> partitionScoresSecond(numberOfPartitions, 0);  // Calculate per incoming edge
    bool firstVertextAlreadyExist(false);
    bool secondVertextAlreadyExist(false);

    int id = 0;
    for (auto partition : partitions) {
        double partitionSize = partition.getVertextCount();
        long thisCostSecond, thisCostFirst = 0;
        std::set<std::string> firstVertextNeighbors = partition.getNeighbors(edge.first);
        std::set<std::string> secondVertextNeighbors = partition.getNeighbors(edge.second);
        double weightedGreedy =
            (1 - (partitionSize / ((double)this->totalVertices / (double)this->numberOfPartitions)));

        if (partition.isExist(edge.first) && partition.isExist(edge.second)) {
            partition.addEdge(edge);
            this->totalEdges += 1;  // TODO: Check whether edge already exist
            return {{edge.first, id}, {edge.second, id}};
        }
        double firstVertextInterCost = firstVertextNeighbors.size();
        if (firstVertextInterCost == 0) firstVertextInterCost = 1;
        double secondVertextInterCost = secondVertextNeighbors.size();
        if (secondVertextInterCost == 0) secondVertextInterCost = 1;

        if (firstVertextNeighbors.size() != 0) {
            if (firstVertextNeighbors.find(edge.second) != firstVertextNeighbors.end())
                return {{edge.first, id}, {edge.second, id}};  // Nothing to do, edge already exist
        }

        partitionScoresFirst[id] = firstVertextInterCost * weightedGreedy;

        if (secondVertextNeighbors.size() != 0) {
            if (secondVertextNeighbors.find(edge.second) != secondVertextNeighbors.end())
                return {{edge.first, id},
                        {edge.second, id}};  // Nothing to do, edge already exist, Because of the symmetrical nature of
                                             // undirected edgelist implementation this is already checked when finding
                                             // neighbors of the first edge above
        }

        partitionScoresSecond[id] = secondVertextInterCost * weightedGreedy;
        id++;
    }
    if (!firstVertextAlreadyExist) this->totalVertices += 1;
    if (!secondVertextAlreadyExist) this->totalVertices += 1;

    int firstIndex =
        distance(partitionScoresFirst.begin(), max_element(partitionScoresFirst.begin(), partitionScoresFirst.end()));

    int secondIndex = distance(partitionScoresSecond.begin(),
                               max_element(partitionScoresSecond.begin(), partitionScoresSecond.end()));
    if (firstIndex == secondIndex) {
        partitions[firstIndex].addEdge(edge);
    } else {
        partitions[firstIndex].addToEdgeCuts(edge.first, edge.second, secondIndex);
        partitions[secondIndex].addToEdgeCuts(edge.second, edge.first, firstIndex);
    }
    this->totalEdges += 1;
    return {{edge.first, firstIndex}, {edge.second, secondIndex}};
}

/**
 * LEOPARD: Locally Estimated Partitioning Algorithm for Robust Distributed graph processing.
 * Score for assigning vertex v to partition S:
 *   score(v, S) = |N(v) ∩ S| - α·(γ/2)·|S|^(γ-1)
 * where:
 *   α = sqrt(k) · m / n^γ,  γ = 1.5
 *   |N(v) ∩ S| = number of already-assigned neighbours of v that reside in S
 *
 * This is the streaming variant (no ripple-effect reassignment).
 **/
partitionedEdge Partitioner::leopardPartitioning(std::pair<std::string, std::string> edge) {
    const double gamma = 1.5;
    const std::string& u = edge.first;
    const std::string& v = edge.second;

    // Initialise per-vertex neighbour-count vectors on first sight
    if (vertexNeighborCounts.find(u) == vertexNeighborCounts.end())
        vertexNeighborCounts[u] = std::vector<int>(this->numberOfPartitions, 0);
    if (vertexNeighborCounts.find(v) == vertexNeighborCounts.end())
        vertexNeighborCounts[v] = std::vector<int>(this->numberOfPartitions, 0);

    // Scoring helper: higher is better
    auto scoreFn = [&](const std::string& vertex, int partId) -> double {
        long m = std::max(this->totalEdges, 1L);
        long n = std::max(this->totalVertices, 1L);
        double alpha = std::sqrt((double)this->numberOfPartitions) * (double)m / std::pow((double)n, gamma);
        double neighborScore = (double)vertexNeighborCounts.at(vertex)[partId];
        double partSize = this->partitions[partId].getVertextCountQuick();
        double penalty = (partSize > 0.0) ? alpha * (gamma / 2.0) * std::pow(partSize, gamma - 1.0) : 0.0;
        return neighborScore - penalty;
    };

    auto bestPartFn = [&](const std::string& vertex) -> int {
        int best = 0;
        double bestScore = scoreFn(vertex, 0);
        for (int i = 1; i < this->numberOfPartitions; i++) {
            double s = scoreFn(vertex, i);
            if (s > bestScore) { bestScore = s; best = i; }
        }
        return best;
    };

    bool uExists = (vertexPartitionAssignment.find(u) != vertexPartitionAssignment.end());
    bool vExists = (vertexPartitionAssignment.find(v) != vertexPartitionAssignment.end());

    // --- Assign u if new ---
    int uPartition;
    if (!uExists) {
        uPartition = bestPartFn(u);
        vertexPartitionAssignment[u] = uPartition;
        this->totalVertices += 1;
    } else {
        uPartition = vertexPartitionAssignment[u];
    }

    // Tell v that it has a neighbour (u) in uPartition, then assign v if new
    vertexNeighborCounts[v][uPartition]++;

    int vPartition;
    if (!vExists) {
        vPartition = bestPartFn(v);
        vertexPartitionAssignment[v] = vPartition;
        this->totalVertices += 1;
    } else {
        vPartition = vertexPartitionAssignment[v];
    }

    // Tell u that it has a neighbour (v) in vPartition
    vertexNeighborCounts[u][vPartition]++;

    // Check if edge already exists (both ends lived in same partition)
    if (uExists && vExists && uPartition == vPartition) {
        auto uNeighbors = this->partitions[uPartition].getNeighbors(u);
        if (uNeighbors.find(v) != uNeighbors.end()) {
            // Undo the neighbour-count increments added above for duplicate
            vertexNeighborCounts[v][uPartition]--;
            vertexNeighborCounts[u][vPartition]--;
            return {{u, uPartition}, {v, vPartition}};
        }
    }

    // Place edge into partition or record as edge-cut
    if (uPartition == vPartition) {
        this->partitions[uPartition].addEdge(edge, this->isDirect);
    } else {
        this->partitions[uPartition].addToEdgeCuts(u, v, vPartition);
        this->partitions[vPartition].addToEdgeCuts(v, u, uPartition);
    }
    this->totalEdges += 1;
    return {{u, uPartition}, {v, vPartition}};
}

/**
 * Score for assigning vertex v to partition S:
 *   score(v, S) = |N(v) ∩ S| - α·γ·|S|^(γ-1)
 * where:
 *   α = k^(γ-1) · m / n^γ,  γ = 1.5
 *   |N(v) ∩ S| = number of already-assigned neighbours of v that reside in S
 **/
partitionedEdge Partitioner::cuttanaPartitioning(std::pair<std::string, std::string> edge) {
    const double gamma = 1.5;
    const std::string& u = edge.first;
    const std::string& v = edge.second;

    // Initialise per-vertex neighbour-count vectors on first sight
    if (vertexNeighborCounts.find(u) == vertexNeighborCounts.end())
        vertexNeighborCounts[u] = std::vector<int>(this->numberOfPartitions, 0);
    if (vertexNeighborCounts.find(v) == vertexNeighborCounts.end())
        vertexNeighborCounts[v] = std::vector<int>(this->numberOfPartitions, 0);

    // Scoring helper: higher is better
    auto scoreFn = [&](const std::string& vertex, int partId) -> double {
        long m = std::max(this->totalEdges, 1L);
        long n = std::max(this->totalVertices, 1L);
        double alpha = std::pow((double)this->numberOfPartitions, gamma - 1.0) * (double)m / std::pow((double)n, gamma);
        double neighborScore = (double)vertexNeighborCounts.at(vertex)[partId];
        double partSize = this->partitions[partId].getVertextCountQuick();
        double penalty = (partSize > 0.0) ? alpha * gamma * std::pow(partSize, gamma - 1.0) : 0.0;
        return neighborScore - penalty;
    };

    auto bestPartFn = [&](const std::string& vertex) -> int {
        int best = 0;
        double bestScore = scoreFn(vertex, 0);
        for (int i = 1; i < this->numberOfPartitions; i++) {
            double s = scoreFn(vertex, i);
            if (s > bestScore) { bestScore = s; best = i; }
        }
        return best;
    };

    bool uExists = (vertexPartitionAssignment.find(u) != vertexPartitionAssignment.end());
    bool vExists = (vertexPartitionAssignment.find(v) != vertexPartitionAssignment.end());

    // --- Assign u if new ---
    int uPartition;
    if (!uExists) {
        uPartition = bestPartFn(u);
        vertexPartitionAssignment[u] = uPartition;
        this->totalVertices += 1;
    } else {
        uPartition = vertexPartitionAssignment[u];
    }

    // Tell v that it has a neighbour (u) in uPartition, then assign v if new
    vertexNeighborCounts[v][uPartition]++;

    int vPartition;
    if (!vExists) {
        vPartition = bestPartFn(v);
        vertexPartitionAssignment[v] = vPartition;
        this->totalVertices += 1;
    } else {
        vPartition = vertexPartitionAssignment[v];
    }

    // Tell u that it has a neighbour (v) in vPartition
    vertexNeighborCounts[u][vPartition]++;

    // Check if edge already exists (both ends lived in same partition)
    if (uExists && vExists && uPartition == vPartition) {
        auto uNeighbors = this->partitions[uPartition].getNeighbors(u);
        if (uNeighbors.find(v) != uNeighbors.end()) {
            // Undo the neighbour-count increments added above for duplicate
            vertexNeighborCounts[v][uPartition]--;
            vertexNeighborCounts[u][vPartition]--;
            return {{u, uPartition}, {v, vPartition}};
        }
    }

    // Place edge into partition or record as edge-cut
    if (uPartition == vPartition) {
        this->partitions[uPartition].addEdge(edge, this->isDirect);
    } else {
        this->partitions[uPartition].addToEdgeCuts(u, v, vPartition);
        this->partitions[vPartition].addToEdgeCuts(v, u, uPartition);
    }
    this->totalEdges += 1;
    return {{u, uPartition}, {v, vPartition}};
}

partitionedEdge Partitioner::hashPartitioning(std::pair<std::string, std::string> edge) {
    int firstIndex = stoi(edge.first) % this->numberOfPartitions;    // Hash partitioning
    int secondIndex = stoi(edge.second) % this->numberOfPartitions;  // Hash partitioning

    if (firstIndex == secondIndex) {
        this->partitions[firstIndex].addEdge(edge, this->isDirect);
    } else {
        this->partitions[firstIndex].addToEdgeCuts(edge.first, edge.second, secondIndex);
        this->partitions[secondIndex].addToEdgeCuts(edge.second, edge.first, firstIndex);
    }
    return {{edge.first, firstIndex}, {edge.second, secondIndex}};
}

void Partitioner::printStats() {
    int id = 0;
    for (auto partition : this->partitions) {
        double vertexCount = partition.getVertextCount();
        double edgesCount = partition.getEdgesCount(this->isDirect);
        double edgeCutsCount = partition.edgeCutsCount();
        double edgeCutRatio = partition.edgeCutsRatio();
        streaming_partitioner_logger.info(std::to_string(id) + " => Vertex count = " + std::to_string(vertexCount));
        streaming_partitioner_logger.info(std::to_string(id) + " => Edges count = " + std::to_string(edgesCount));
        streaming_partitioner_logger.info(std::to_string(id) +
                                          " => Edge cuts count = " + std::to_string(edgeCutsCount));
        streaming_partitioner_logger.info(std::to_string(id) + " => Cut ratio = " + std::to_string(edgeCutRatio));
        id++;
    }
}


void Partitioner::updateMetaDB() {
    double vertexCount = 0;
    double edgesCount = 0;
    double edgeCutsCount = 0;
    for (auto partition : this->partitions) {
        vertexCount += partition.getVertextCountQuick();
        edgesCount += partition.getEdgesCount(this->isDirect);
        edgeCutsCount += partition.edgeCutsCount();
    }
    double numberOfEdges = edgesCount + edgeCutsCount/2;

    std::time_t time = chrono::system_clock::to_time_t(chrono::system_clock::now());
    string uploadEndTime = ctime(&time);
    std::string sqlStatement = "UPDATE graph SET vertexcount = vertexcount+" + std::to_string(vertexCount) +
            " ,upload_end_time = \"" + uploadEndTime +
            "\" ,graph_status_idgraph_status = " + to_string(Conts::GRAPH_STATUS::OPERATIONAL) +
            " ,edgecount = edgecount+" + std::to_string(numberOfEdges) +
            " WHERE idgraph = " + std::to_string(this->graphID);
    this->sqlite->runUpdate(sqlStatement);
    streaming_partitioner_logger.info("Successfully updated metaDB");
}

/**
 * Greedy vertex assignment objectives of minimizing the number of cut edges
and balancing of the partition sizes. Assign the vertext to partition P that maximize the partition score
 * |N(v) ∩ Si| + ∂c(|Si|)
 * |N(v) ∩ Si| =  number of neighbours of vertex v that are assigned to partition Si.
 * ∂c(|Si|) = the marginal cost of increasing the partition i by one additional vertex.
 *
 * Intra-partition cost function : c(x) = αx^γ, for α > 0 and γ ≥ 1 where x = vertex cardinality
 *   α = m*(k^γ-1) / (n^γ)
 *   Total number of vertices and edges in the graph denoted as |V| = n and |E| = m.
 *   k is number of partitions
 **/
partitionedEdge Partitioner::fennelPartitioning(std::pair<std::string, std::string> edge) {
    std::vector<double> partitionScoresFirst(numberOfPartitions, 0);   // Calculate per incoming edge
    std::vector<double> partitionScoresSecond(numberOfPartitions, 0);  // Calculate per incoming edge
    const double gamma = 3 / 2.0;
    const double alpha =
        this->totalEdges * pow(this->numberOfPartitions, (gamma - 1)) / pow(this->totalVertices, gamma);
    bool firstVertextAlreadyExist(false);
    bool secondVertextAlreadyExist(false);

    int id = 0;
    for (auto& partition : partitions) {
        std::set<std::string> firstVertextNeighbors = partition.getNeighbors(edge.first);
        std::set<std::string> secondVertextNeighbors = partition.getNeighbors(edge.second);
        double firstVertextIntraCost;
        double secondVertextIntraCost;
        if (partition.isExist(edge.first) && partition.isExist(edge.second)) {
            partition.addEdge(edge);
            this->totalEdges += 1;  // TODO: Check whether edge already exist
            return {{edge.first, id}, {edge.second, id}};
        }
        double firstVertextInterCost = firstVertextNeighbors.size();
        double secondVertextInterCost = secondVertextNeighbors.size();

        double partitionSize = partition.getVertextCountQuick();
        firstVertextIntraCost = alpha * (pow(partitionSize + 1, gamma) - pow(partitionSize, gamma));
        secondVertextIntraCost = firstVertextIntraCost;

        if (firstVertextNeighbors.size() != 0) {
            if (firstVertextNeighbors.find(edge.second) != firstVertextNeighbors.end())
                return {{edge.first, id}, {edge.second, id}};  // Nothing to do, edge already exisit
        }
        if (secondVertextNeighbors.size() != 0) {
            if (secondVertextNeighbors.find(edge.first) != secondVertextNeighbors.end())
                return {{edge.first, id},
                        {edge.second, id}};
            // Nothing to do, the edge already exist
        }


        partitionScoresFirst[id] = firstVertextInterCost - firstVertextIntraCost;
        partitionScoresSecond[id] = secondVertextInterCost - secondVertextIntraCost;
        id++;
    }
    if (!firstVertextAlreadyExist) this->totalVertices += 1;
    if (!secondVertextAlreadyExist) this->totalVertices += 1;

    int firstIndex =
        distance(partitionScoresFirst.begin(), max_element(partitionScoresFirst.begin(), partitionScoresFirst.end()));

    int secondIndex = firstIndex;  // minimize edge cuts
        partitions[firstIndex].addEdge(edge);

    this->totalEdges += 1;
    return {{edge.first, firstIndex}, {edge.second, secondIndex}};
}

/**
 * DEPRECATED: With new JSON edge schema
 * Expect a space seperated pair of vertexts representing an edge in the graph.
 **/
std::pair<long, long> Partitioner::deserialize(std::string data) {
    std::vector<std::string> v = Partition::_split(data, ' ');
    streaming_partitioner_logger.debug("Vertext/Node 1 = " + stoi(v[0]));
    streaming_partitioner_logger.debug("Vertext/Node 2 = " + stoi(v[1]));
    return {stoi(v[0]), stoi(v[1])};
}
