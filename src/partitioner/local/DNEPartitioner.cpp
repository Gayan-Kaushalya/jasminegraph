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

#include "DNEPartitioner.h"
#include "../../util/logger/Logger.h"
#include "../../centralstore/JasmineGraphHashMapCentralStore.h"
#include "../../localstore/JasmineGraphHashMapLocalStore.h"
#include "../../util/Utils.h"

#include <filesystem>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cmath>
#include <random>
#include <functional>

using namespace std;

Logger dne_partitioner_logger;

DNEPartitioner::DNEPartitioner(SQLiteDBInterface *sqlite) {
    this->sqlite = sqlite;
    this->totalEdges = 0;
    this->edgeCuts = 0;
    this->numPartitions = 0;
    this->expandRatio = 0.1;
    this->balanceFactor = 1.01;
}

bool DNEPartitioner::loadGraph(const string &graphPath) {
    dne_partitioner_logger.info("Loading graph from: " + graphPath);

    ifstream inputFile(graphPath);
    if (!inputFile.is_open()) {
        dne_partitioner_logger.error("Failed to open graph file: " + graphPath);
        return false;
    }

    string line;
    size_t lineCount = 0;

    while (getline(inputFile, line)) {
        lineCount++;

        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }

        istringstream iss(line);
        vertex_id source, target;

        if (iss >> source >> target) {
            adjacencyList[source].push_back(target);
            adjacencyList[target].push_back(source);
            totalEdges++;
        }
    }

    inputFile.close();

    dne_partitioner_logger.info("Loaded " + to_string(adjacencyList.size()) +
                                " vertices and " + to_string(totalEdges) + " edges");
    return true;
}

partition_id DNEPartitioner::hashAssign(vertex_id src, vertex_id dst) const {
    // 2D-hash assignment, adapted from DistributedNE's MetaD::getMaster()
    // Uses a grid-based hashing scheme for initial edge distribution
    size_t numParts = static_cast<size_t>(numPartitions);
    size_t rows = static_cast<size_t>(std::ceil(std::sqrt(static_cast<double>(numParts))));
    size_t cols = (numParts + rows - 1) / rows;

    size_t srcBucket = static_cast<size_t>(src) % rows;
    size_t dstBucket = static_cast<size_t>(dst) % cols;
    size_t partId = srcBucket * cols + dstBucket;
    
    // Clamp to valid partition range
    if (partId >= numParts) {
        partId = partId % numParts;
    }
    return static_cast<partition_id>(partId);
}

void DNEPartitioner::expandVertex(vertex_id v, partition_id p) {
    // Assign all unallocated edges incident to vertex v to partition p
    const auto &neighbors = adjacencyList[v];
    for (vertex_id neighbor : neighbors) {
        auto edgeKey = make_pair(min(v, neighbor), max(v, neighbor));
        if (edgePartition.find(edgeKey) == edgePartition.end()) {
            // This edge is unallocated — assign it
            edgePartition[edgeKey] = p;
            partitionEdgeCounts[p]++;

            // Decrease vertex scores for both endpoints
            if (vertexScore.count(v) && vertexScore[v] > 0) {
                vertexScore[v]--;
            }
            if (vertexScore.count(neighbor) && vertexScore[neighbor] > 0) {
                vertexScore[neighbor]--;
            }
        }
    }
}

void DNEPartitioner::assignPartitions() {
    dne_partitioner_logger.info("Starting NE edge partitioning");

    partitionEdgeCounts.resize(numPartitions, 0);

    // Compute initial vertex scores (number of incident edges)
    for (const auto &entry : adjacencyList) {
        vertexScore[entry.first] = entry.second.size();
    }

    // Phase 1: Initial 2D-hash assignment
    // Assign edges using hash to get an initial distribution
    dne_partitioner_logger.info("Phase 1: 2D-hash initial assignment");
    for (const auto &entry : adjacencyList) {
        vertex_id src = entry.first;
        for (vertex_id dst : entry.second) {
            if (src < dst) {  // Process each undirected edge once
                auto edgeKey = make_pair(src, dst);
                if (edgePartition.find(edgeKey) == edgePartition.end()) {
                    partition_id p = hashAssign(src, dst);
                    edgePartition[edgeKey] = p;
                    partitionEdgeCounts[p]++;
                    
                    if (vertexScore.count(src) && vertexScore[src] > 0) {
                        vertexScore[src]--;
                    }
                    if (vertexScore.count(dst) && vertexScore[dst] > 0) {
                        vertexScore[dst]--;
                    }
                }
            }
        }
    }
    
    dne_partitioner_logger.info("Initial assignment complete. Assigned " + 
                                to_string(edgePartition.size()) + " edges");

    // Phase 2: Neighbor Expansion
    // Build boundary queue: vertices that have edges in multiple partitions
    dne_partitioner_logger.info("Phase 2: Neighbor expansion refinement");

    // Determine which partitions each vertex touches
    unordered_map<vertex_id, set<partition_id>> vertexPartitions;
    for (const auto &ep : edgePartition) {
        vertex_id u = ep.first.first;
        vertex_id v = ep.first.second;
        partition_id p = ep.second;
        vertexPartitions[u].insert(p);
        vertexPartitions[v].insert(p);
    }

    // Build a priority queue of boundary vertices (vertices touching multiple partitions)
    // Scored by number of partitions they appear in (lower = better candidate for expansion)
    priority_queue<BoundaryEntry, vector<BoundaryEntry>, greater<BoundaryEntry>> boundaryQueue;
    
    for (const auto &vp : vertexPartitions) {
        if (vp.second.size() > 1) {
            // This vertex is on a boundary
            // Score = number of unallocated edges (lower is better for expansion)
            BoundaryEntry entry;
            entry.score = vertexScore[vp.first];
            entry.vertex = vp.first;
            // Pick the partition where this vertex has the most edges
            unordered_map<partition_id, size_t> partCounts;
            for (vertex_id neighbor : adjacencyList[vp.first]) {
                auto edgeKey = make_pair(min(vp.first, neighbor), max(vp.first, neighbor));
                auto it = edgePartition.find(edgeKey);
                if (it != edgePartition.end()) {
                    partCounts[it->second]++;
                }
            }
            partition_id bestPart = 0;
            size_t bestCount = 0;
            for (const auto &pc : partCounts) {
                if (pc.second > bestCount) {
                    bestCount = pc.second;
                    bestPart = pc.first;
                }
            }
            entry.partition = bestPart;
            boundaryQueue.push(entry);
        }
    }

    // Balance threshold: max edges per partition
    size_t avgEdgesPerPartition = totalEdges / numPartitions;
    size_t edgeThreshold = static_cast<size_t>(avgEdgesPerPartition * balanceFactor);

    dne_partitioner_logger.info("Edge threshold per partition: " + to_string(edgeThreshold));
    dne_partitioner_logger.info("Boundary queue size: " + to_string(boundaryQueue.size()));

    // Iterative expansion
    int iteration = 0;
    int maxIterations = 100;  // Safety limit

    while (!boundaryQueue.empty() && iteration < maxIterations) {
        size_t numExpand = static_cast<size_t>(expandRatio * boundaryQueue.size());
        if (numExpand < 1) numExpand = 1;

        bool madeProgress = false;

        for (size_t i = 0; i < numExpand && !boundaryQueue.empty(); i++) {
            BoundaryEntry entry = boundaryQueue.top();
            boundaryQueue.pop();

            partition_id targetPart = entry.partition;

            // Check balance constraint
            if (partitionEdgeCounts[targetPart] >= edgeThreshold) {
                continue;
            }

            // Reassign edges of this vertex's neighbors to improve locality
            vertex_id v = entry.vertex;
            const auto &neighbors = adjacencyList[v];
            
            for (vertex_id neighbor : neighbors) {
                auto edgeKey = make_pair(min(v, neighbor), max(v, neighbor));
                auto it = edgePartition.find(edgeKey);
                if (it != edgePartition.end() && it->second != targetPart) {
                    partition_id oldPart = it->second;
                    
                    // Only reassign if the source partition won't become too small
                    // and the target won't become too large
                    if (partitionEdgeCounts[oldPart] > avgEdgesPerPartition / 2 &&
                        partitionEdgeCounts[targetPart] < edgeThreshold) {
                        it->second = targetPart;
                        partitionEdgeCounts[oldPart]--;
                        partitionEdgeCounts[targetPart]++;
                        madeProgress = true;
                    }
                }
            }
        }

        if (!madeProgress) break;

        // Rebuild boundary queue with updated scores
        // Clear and rebuild
        while (!boundaryQueue.empty()) boundaryQueue.pop();

        vertexPartitions.clear();
        for (const auto &ep : edgePartition) {
            vertex_id u = ep.first.first;
            vertex_id v = ep.first.second;
            partition_id p = ep.second;
            vertexPartitions[u].insert(p);
            vertexPartitions[v].insert(p);
        }

        for (const auto &vp : vertexPartitions) {
            if (vp.second.size() > 1) {
                BoundaryEntry entry;
                entry.score = vp.second.size();  // Score by replication factor
                entry.vertex = vp.first;
                
                // Pick partition where vertex has most edges
                unordered_map<partition_id, size_t> partCounts;
                for (vertex_id neighbor : adjacencyList[vp.first]) {
                    auto edgeKey = make_pair(min(vp.first, neighbor), max(vp.first, neighbor));
                    auto it = edgePartition.find(edgeKey);
                    if (it != edgePartition.end()) {
                        partCounts[it->second]++;
                    }
                }
                partition_id bestPart = 0;
                size_t bestCount = 0;
                for (const auto &pc : partCounts) {
                    if (pc.second > bestCount) {
                        bestCount = pc.second;
                        bestPart = pc.first;
                    }
                }
                entry.partition = bestPart;
                boundaryQueue.push(entry);
            }
        }

        iteration++;
    }

    dne_partitioner_logger.info("NE expansion completed after " + to_string(iteration) + " iterations");
    
    // Log partition edge counts
    for (int i = 0; i < numPartitions; i++) {
        dne_partitioner_logger.info("Partition " + to_string(i) + 
                                    " edges: " + to_string(partitionEdgeCounts[i]));
    }
}

void DNEPartitioner::calculateEdgeCuts() {
    edgeCuts = 0;

    // In edge partitioning, "edge cuts" correspond to vertex replications
    // Count vertices that appear in multiple partitions
    unordered_map<vertex_id, set<partition_id>> vertexPartitions;
    for (const auto &ep : edgePartition) {
        vertex_id u = ep.first.first;
        vertex_id v = ep.first.second;
        partition_id p = ep.second;
        vertexPartitions[u].insert(p);
        vertexPartitions[v].insert(p);
    }

    size_t totalReplicas = 0;
    for (const auto &vp : vertexPartitions) {
        totalReplicas += vp.second.size();
    }

    // Replication factor = total replicas / unique vertices
    double replicationFactor = static_cast<double>(totalReplicas) / vertexPartitions.size();

    // For compatibility with the Jasminegraph edge cut metric, count edges whose
    // endpoints would be in different partitions (using vertex majority partition)
    // Determine primary partition for each vertex (partition with most of its edges)
    unordered_map<vertex_id, partition_id> vertexPrimaryPartition;
    for (const auto &vp : vertexPartitions) {
        if (vp.second.size() == 1) {
            vertexPrimaryPartition[vp.first] = *vp.second.begin();
        } else {
            unordered_map<partition_id, size_t> partCounts;
            for (vertex_id neighbor : adjacencyList[vp.first]) {
                auto edgeKey = make_pair(min(vp.first, neighbor), max(vp.first, neighbor));
                auto it = edgePartition.find(edgeKey);
                if (it != edgePartition.end()) {
                    partCounts[it->second]++;
                }
            }
            partition_id bestPart = 0;
            size_t bestCount = 0;
            for (const auto &pc : partCounts) {
                if (pc.second > bestCount) {
                    bestCount = pc.second;
                    bestPart = pc.first;
                }
            }
            vertexPrimaryPartition[vp.first] = bestPart;
        }
    }

    for (const auto &entry : adjacencyList) {
        vertex_id source = entry.first;
        for (vertex_id target : entry.second) {
            if (source < target) {
                if (vertexPrimaryPartition[source] != vertexPrimaryPartition[target]) {
                    edgeCuts++;
                }
            }
        }
    }

    dne_partitioner_logger.info("Edge cuts: " + to_string(edgeCuts) +
                                " (" + to_string((edgeCuts * 100.0) / totalEdges) + "%)");
    dne_partitioner_logger.info("Replication factor: " + to_string(replicationFactor));
}

bool DNEPartitioner::writePartitions(const string &outputPath) {
    dne_partitioner_logger.info("Writing partitions with central/local store format to: " + outputPath);

    try {
        // Create output directory if needed
        std::filesystem::path basePath(outputPath);
        std::filesystem::path parentDir = basePath.parent_path();
        if (!parentDir.empty() && !std::filesystem::exists(parentDir)) {
            std::filesystem::create_directories(parentDir);
        }

        // Determine primary partition for each vertex (most edges in that partition)
        unordered_map<vertex_id, partition_id> vertexPrimaryPartition;
        unordered_map<vertex_id, set<partition_id>> vertexPartitions;
        
        for (const auto &ep : edgePartition) {
            vertex_id u = ep.first.first;
            vertex_id v = ep.first.second;
            partition_id p = ep.second;
            vertexPartitions[u].insert(p);
            vertexPartitions[v].insert(p);
        }

        for (const auto &vp : vertexPartitions) {
            if (vp.second.size() == 1) {
                vertexPrimaryPartition[vp.first] = *vp.second.begin();
            } else {
                unordered_map<partition_id, size_t> partCounts;
                for (vertex_id neighbor : adjacencyList[vp.first]) {
                    auto edgeKey = make_pair(min(vp.first, neighbor), max(vp.first, neighbor));
                    auto it = edgePartition.find(edgeKey);
                    if (it != edgePartition.end()) {
                        partCounts[it->second]++;
                    }
                }
                partition_id bestPart = 0;
                size_t bestCount = 0;
                for (const auto &pc : partCounts) {
                    if (pc.second > bestCount) {
                        bestCount = pc.second;
                        bestPart = pc.first;
                    }
                }
                vertexPrimaryPartition[vp.first] = bestPart;
            }
        }

        // Track vertices per partition
        std::vector<std::set<vertex_id>> partitionVerticesSet(numPartitions);
        std::vector<size_t> localEdgeCounts(numPartitions, 0);
        std::vector<size_t> centralEdgeCounts(numPartitions, 0);

        // Build edge maps using sets for deduplication
        std::vector<std::map<int, std::unordered_set<int>>> localStoreSets(numPartitions);
        std::vector<std::map<int, std::unordered_set<int>>> centralStoreSets(numPartitions);
        std::vector<std::map<int, std::unordered_set<int>>> duplicateCentralStoreSets(numPartitions);

        // Extract graphID from outputPath
        string graphID = "0";
        size_t lastSlash = outputPath.find_last_of("/\\");
        if (lastSlash != string::npos) {
            string filename = outputPath.substr(lastSlash + 1);
            size_t firstUnderscore = filename.find('_');
            if (firstUnderscore != string::npos) {
                graphID = filename.substr(0, firstUnderscore);
            }
        }

        // Process all edges in the adjacency list
        for (const auto &entry : adjacencyList) {
            vertex_id source = entry.first;
            partition_id sourcePart = vertexPrimaryPartition[source];

            partitionVerticesSet[sourcePart].insert(source);

            for (vertex_id target : entry.second) {
                partition_id targetPart = vertexPrimaryPartition[target];
                partitionVerticesSet[targetPart].insert(target);

                if (sourcePart == targetPart) {
                    // Local edge
                    localStoreSets[sourcePart][source].insert(target);
                    if (source < target) {
                        localEdgeCounts[sourcePart]++;
                    }
                } else {
                    // Cross-partition edge
                    centralStoreSets[sourcePart][source].insert(target);
                    duplicateCentralStoreSets[targetPart][source].insert(target);
                    if (source < target) {
                        centralEdgeCounts[sourcePart]++;
                    }
                }
            }
        }

        // Convert sets to vectors for serialization
        std::vector<std::map<int, std::vector<int>>> localStoreMaps(numPartitions);
        std::vector<std::map<int, std::vector<int>>> centralStoreMaps(numPartitions);
        std::vector<std::map<int, std::vector<int>>> duplicateCentralStoreMaps(numPartitions);

        for (size_t i = 0; i < numPartitions; i++) {
            for (const auto &entry : localStoreSets[i]) {
                localStoreMaps[i][entry.first] = std::vector<int>(entry.second.begin(), entry.second.end());
            }
            for (const auto &entry : centralStoreSets[i]) {
                centralStoreMaps[i][entry.first] = std::vector<int>(entry.second.begin(), entry.second.end());
            }
            for (const auto &entry : duplicateCentralStoreSets[i]) {
                duplicateCentralStoreMaps[i][entry.first] = std::vector<int>(entry.second.begin(), entry.second.end());
            }
        }

        // Serialize and compress files using FlatBuffers format
        for (size_t i = 0; i < numPartitions; i++) {
            string localFilename = outputPath + to_string(i);
            string centralFilename = outputPath.substr(0, outputPath.find_last_of("/\\") + 1) +
                                     graphID + "_centralstore_" + to_string(i);
            string duplicateCentralFilename = outputPath.substr(0, outputPath.find_last_of("/\\") + 1) +
                                              graphID + "_centralstore_dp_" + to_string(i);

            // Store local store
            if (!JasmineGraphHashMapLocalStore::storePartEdgeMap(localStoreMaps[i], localFilename)) {
                dne_partitioner_logger.error("Failed to serialize local store for partition " + to_string(i));
                return false;
            }
            Utils::compressFile(localFilename);
            partitionFileMap[i] = localFilename + ".gz";

            // Store central store
            if (!JasmineGraphHashMapCentralStore::storePartEdgeMap(centralStoreMaps[i], centralFilename)) {
                dne_partitioner_logger.error("Failed to serialize central store for partition " + to_string(i));
                return false;
            }
            Utils::compressFile(centralFilename);
            centralStoreFileList[i] = centralFilename + ".gz";

            // Store duplicate central store
            if (!JasmineGraphHashMapCentralStore::storePartEdgeMap(duplicateCentralStoreMaps[i],
                                                                   duplicateCentralFilename)) {
                dne_partitioner_logger.error("Failed to serialize duplicate central store for partition " +
                                             to_string(i));
                return false;
            }
            Utils::compressFile(duplicateCentralFilename);
            centralStoreDuplicateFileList[i] = duplicateCentralFilename + ".gz";

            dne_partitioner_logger.info("Serialized and compressed partition " + to_string(i));
        }

        // Store partition statistics
        partitionVertexCounts.clear();
        partitionEdgeCountsVec.clear();
        for (size_t i = 0; i < numPartitions; i++) {
            partitionVertexCounts.push_back(partitionVerticesSet[i].size());
            partitionEdgeCountsVec.push_back(localEdgeCounts[i] + centralEdgeCounts[i]);
        }

        dne_partitioner_logger.info("Successfully wrote " + to_string(numPartitions) +
                                    " partition files");

        for (size_t i = 0; i < numPartitions; i++) {
            dne_partitioner_logger.info("Partition " + to_string(i) +
                                        ": vertices=" + to_string(partitionVerticesSet[i].size()) +
                                        ", local edges=" + to_string(localEdgeCounts[i]) +
                                        ", central edges=" + to_string(centralEdgeCounts[i]));
        }

        return true;

    } catch (const std::exception &e) {
        dne_partitioner_logger.error("Error writing partitions: " + string(e.what()));
        return false;
    }
}

std::vector<std::map<int, std::string>> DNEPartitioner::partitionGraph(int graphID, const string &graphPath,
                                                                        const string &outputPath, int numPartitions) {
    dne_partitioner_logger.info("Starting DNE partitioning for graph ID: " + to_string(graphID));
    dne_partitioner_logger.info("Input graph: " + graphPath);
    dne_partitioner_logger.info("Output path: " + outputPath);
    dne_partitioner_logger.info("Number of partitions: " + to_string(numPartitions));

    this->numPartitions = numPartitions;

    // Check if input graph exists
    if (!std::filesystem::exists(graphPath)) {
        dne_partitioner_logger.error("Input graph file does not exist: " + graphPath);
        return fullFileList;
    }

    // Load the graph
    if (!loadGraph(graphPath)) {
        return fullFileList;
    }

    // Run NE partitioning algorithm
    assignPartitions();

    // Calculate edge cuts / replication factor
    calculateEdgeCuts();

    // Write partitions to files
    if (!writePartitions(outputPath)) {
        return fullFileList;
    }

    // Update metadata database
    try {
        string sqlStatement = "UPDATE graph SET vertexcount = '" + to_string(adjacencyList.size()) +
                              "', centralpartitioncount = '" + to_string(numPartitions) +
                              "', edgecount = '" + to_string(totalEdges) +
                              "', id_algorithm = 'dne' WHERE idgraph = '" + to_string(graphID) + "'";
        sqlite->runUpdate(sqlStatement);

        dne_partitioner_logger.info("Updated graph table with statistics");

        for (size_t i = 0; i < numPartitions; i++) {
            string partitionInsert =
                "INSERT INTO partition (idpartition, graph_idgraph, vertexcount, central_vertexcount, edgecount) "
                "VALUES('" + to_string(i) + "', '" + to_string(graphID) + "', '" +
                to_string(partitionVertexCounts[i]) + "', '0', '" +
                to_string(partitionEdgeCountsVec[i]) + "')";
            sqlite->runUpdate(partitionInsert);
        }

        dne_partitioner_logger.info("Successfully partitioned graph " + to_string(graphID) +
                                    " using DNE algorithm with " + to_string(numPartitions) + " partitions");
    } catch (const std::exception &e) {
        dne_partitioner_logger.error("Error updating database: " + string(e.what()));
        return fullFileList;
    }

    // Build and return file lists for worker distribution
    fullFileList.push_back(partitionFileMap);
    fullFileList.push_back(centralStoreFileList);
    fullFileList.push_back(centralStoreDuplicateFileList);
    fullFileList.push_back(std::map<int, std::string>());  // Empty attribute files
    fullFileList.push_back(std::map<int, std::string>());  // Empty central attribute files
    fullFileList.push_back(std::map<int, std::string>());  // Empty composite central files

    return fullFileList;
}
