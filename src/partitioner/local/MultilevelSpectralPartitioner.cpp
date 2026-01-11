/**
Copyright 2025 JasmineGraph Team
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

#include "MultilevelSpectralPartitioner.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iostream>
#include <limits>
#include <numeric>
#include <sstream>
#include <chrono>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "../../util/Conts.h"
#include "../../util/Utils.h"
#include "../../util/logger/Logger.h"

Logger multilevel_logger;

// ============================================================================
// MultilevelSpectralPartitioner Implementation
// ============================================================================

MultilevelSpectralPartitioner::MultilevelSpectralPartitioner(SQLiteDBInterface *sqlite, const MultilevelConfig &config)
    : sqlite(sqlite), config(config), graphID(0), vertexCount(0), edgeCount(0), coarsenLevels(0) {
    multilevel_logger.log("Multilevel Spectral Partitioner initialized", "info");
    multilevel_logger.log("Config: coarseLimit=" + std::to_string(config.coarseLimit) + 
                         ", maxK=" + std::to_string(config.maxK) + 
                         ", balanceEpsilon=" + std::to_string(config.balanceEpsilon), "info");
}

void MultilevelSpectralPartitioner::loadGraph(const string &inputFilePath, int graphID) {
    multilevel_logger.log("Loading graph from: " + inputFilePath, "info");
    this->graphID = graphID;
    this->outputFilePath = Utils::getHomeDir() + "/.jasminegraph/tmp/" + std::to_string(this->graphID);

    Utils::createDirectory(Utils::getHomeDir() + "/.jasminegraph/tmp");
    Utils::createDirectory(this->outputFilePath);

    std::ifstream inFile(inputFilePath);
    if (!inFile.is_open()) {
        multilevel_logger.log("Failed to open file: " + inputFilePath, "error");
        return;
    }

    string line;
    char delimiter = ' ';

    // Auto-detect delimiter
    std::getline(inFile, line);
    if (!line.empty()) {
        if (line.find('\t') != std::string::npos) {
            delimiter = '\t';
        } else if (line.find(',') != std::string::npos) {
            delimiter = ',';
        }
    }

    // Reset file to beginning
    inFile.clear();
    inFile.seekg(0);

    int sequentialId = 0;

    while (std::getline(inFile, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::istringstream iss(line);
        string srcStr, dstStr;
        std::getline(iss, srcStr, delimiter);
        iss >> dstStr;

        int src = std::stoi(srcStr);
        int dst = std::stoi(dstStr);

        // Map vertices to sequential IDs
        if (vertexIdMap.find(src) == vertexIdMap.end()) {
            vertexIdMap[src] = sequentialId;
            reverseVertexMap.push_back(src);
            sequentialId++;
        }
        if (vertexIdMap.find(dst) == vertexIdMap.end()) {
            vertexIdMap[dst] = sequentialId;
            reverseVertexMap.push_back(dst);
            sequentialId++;
        }

        int mappedSrc = vertexIdMap[src];
        int mappedDst = vertexIdMap[dst];

        // Build adjacency list (undirected graph)
        adjList[mappedSrc].push_back(mappedDst);
        if (mappedSrc != mappedDst) {  // Avoid double-counting self-loops
            adjList[mappedDst].push_back(mappedSrc);
        }
        edgeCount++;
    }

    vertexCount = reverseVertexMap.size();
    inFile.close();

    multilevel_logger.log("Graph loaded: " + std::to_string(vertexCount) + " vertices, " + 
                         std::to_string(edgeCount) + " edges", "info");
}

CoarseGraph MultilevelSpectralPartitioner::convertToCoarseGraph() {
    CoarseGraph graph(vertexCount);
    graph.vertexWeights.assign(vertexCount, 1);  // Initial weight = 1 per vertex

    // Convert adjacency list to CSR format
    graph.xadj[0] = 0;
    for (int i = 0; i < vertexCount; ++i) {
        const auto &neighbors = adjList[i];
        for (int j : neighbors) {
            graph.adjncy.push_back(j);
        }
        graph.xadj[i + 1] = graph.adjncy.size();
    }

    return graph;
}

void MultilevelSpectralPartitioner::heavyEdgeMatching(const CoarseGraph &graph, vector<int> &match) {
    int n = graph.numVertices;
    match.assign(n, -1);

    #ifdef _OPENMP
    if (config.useParallelMatching && n > 10000) {
        // Parallel matching for large graphs
        #pragma omp parallel for schedule(dynamic, 64)
        for (int u = 0; u < n; ++u) {
            if (match[u] != -1) continue;

            int best = -1;
            int maxWeight = 0;

            // Find heaviest unmatched neighbor
            for (int e = graph.xadj[u]; e < graph.xadj[u + 1]; ++e) {
                int v = graph.adjncy[e];
                if (match[v] == -1) {
                    // Weight = number of shared edges (simple heuristic)
                    int weight = 1;
                    if (weight > maxWeight) {
                        maxWeight = weight;
                        best = v;
                    }
                }
            }

            // Attempt to match
            if (best != -1) {
                #pragma omp critical
                {
                    if (match[u] == -1 && match[best] == -1) {
                        match[u] = best;
                        match[best] = u;
                    }
                }
            }
        }
    } else
    #endif
    {
        // Serial matching
        for (int u = 0; u < n; ++u) {
            if (match[u] != -1) continue;

            int best = -1;
            
            // Find first unmatched neighbor (simple heavy edge matching)
            for (int e = graph.xadj[u]; e < graph.xadj[u + 1]; ++e) {
                int v = graph.adjncy[e];
                if (match[v] == -1) {
                    best = v;
                    break;
                }
            }

            if (best != -1 && match[best] == -1) {
                match[u] = best;
                match[best] = u;
            }
        }
    }

    // Handle unmatched vertices (match to themselves)
    for (int u = 0; u < n; ++u) {
        if (match[u] == -1) {
            match[u] = u;
        }
    }
}

CoarseGraph MultilevelSpectralPartitioner::coarsenGraph(const CoarseGraph &graph, 
                                                        const vector<int> &match, 
                                                        vector<int> &fine2coarse) {
    int n = graph.numVertices;
    fine2coarse.resize(n);

    // Assign coarse vertex IDs
    int coarseId = 0;
    for (int i = 0; i < n; ++i) {
        if (match[i] >= i) {  // Representative vertex
            fine2coarse[i] = coarseId++;
        }
    }

    // Map all vertices to their coarse representatives
    for (int i = 0; i < n; ++i) {
        if (match[i] < i) {
            fine2coarse[i] = fine2coarse[match[i]];
        }
    }

    CoarseGraph coarse(coarseId);
    coarse.vertexWeights.assign(coarseId, 0);

    // Aggregate vertex weights
    for (int i = 0; i < n; ++i) {
        int c = fine2coarse[i];
        coarse.vertexWeights[c] += graph.vertexWeights[i];
    }

    // Build coarse adjacency
    std::map<int, std::map<int, int>> coarseAdj;  // coarseU -> (coarseV -> edgeWeight)

    for (int u = 0; u < n; ++u) {
        int cu = fine2coarse[u];
        for (int e = graph.xadj[u]; e < graph.xadj[u + 1]; ++e) {
            int v = graph.adjncy[e];
            int cv = fine2coarse[v];
            if (cu != cv) {  // No self-loops
                coarseAdj[cu][cv]++;
            }
        }
    }

    // Convert to CSR
    coarse.xadj[0] = 0;
    for (int cu = 0; cu < coarseId; ++cu) {
        for (const auto &entry : coarseAdj[cu]) {
            coarse.adjncy.push_back(entry.first);
        }
        coarse.xadj[cu + 1] = coarse.adjncy.size();
    }

    return coarse;
}

CoarseGraph MultilevelSpectralPartitioner::buildHierarchy() {
    multilevel_logger.log("Building coarsening hierarchy", "info");
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    CoarseGraph currentGraph = convertToCoarseGraph();
    graphHierarchy.clear();
    fine2coarseMappings.clear();
    coarsenLevels = 0;

    while (currentGraph.numVertices > config.coarseLimit && coarsenLevels < config.maxCoarsenLevels) {
        graphHierarchy.push_back(currentGraph);

        vector<int> match;
        heavyEdgeMatching(currentGraph, match);

        vector<int> fine2coarse;
        CoarseGraph coarseGraph = coarsenGraph(currentGraph, match, fine2coarse);

        fine2coarseMappings.push_back(fine2coarse);

        double reductionRatio = (double)coarseGraph.numVertices / currentGraph.numVertices;
        multilevel_logger.log("Level " + std::to_string(coarsenLevels) + ": " + 
                             std::to_string(currentGraph.numVertices) + " -> " + 
                             std::to_string(coarseGraph.numVertices) + " vertices (" + 
                             std::to_string((int)(reductionRatio * 100)) + "%)", "info");

        // Check if coarsening is making progress
        if (reductionRatio > 0.95) {
            multilevel_logger.log("Coarsening stalled (reduction < 5%), stopping", "info");
            break;
        }

        currentGraph = coarseGraph;
        coarsenLevels++;
    }

    graphHierarchy.push_back(currentGraph);  // Add coarsest graph

    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    multilevel_logger.log("Coarsening complete: " + std::to_string(coarsenLevels) + " levels, " + 
                         "coarsest graph has " + std::to_string(currentGraph.numVertices) + " vertices", "info");
    multilevel_logger.log("Coarsening time: " + std::to_string(duration.count()) + " ms", "info");

    return currentGraph;
}

std::unordered_map<int, vector<int>> MultilevelSpectralPartitioner::convertToAdjList(const CoarseGraph &graph) {
    std::unordered_map<int, vector<int>> adjList;
    
    for (int i = 0; i < graph.numVertices; ++i) {
        vector<int> neighbors;
        for (int e = graph.xadj[i]; e < graph.xadj[i + 1]; ++e) {
            neighbors.push_back(graph.adjncy[e]);
        }
        if (!neighbors.empty()) {
            adjList[i] = neighbors;
        }
    }
    
    return adjList;
}

vector<int> MultilevelSpectralPartitioner::initialPartition(const CoarseGraph &coarseGraph, int numPartitions) {
    multilevel_logger.log("Computing initial partition on coarsest graph", "info");
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Use existing SpectralPartitioner for the coarse graph
    SpectralPartitioner spectral(sqlite);
    
    // Temporarily save coarse graph to file
    string tempFile = outputFilePath + "/coarse_graph_temp.txt";
    std::ofstream outFile(tempFile);
    
    for (int u = 0; u < coarseGraph.numVertices; ++u) {
        for (int e = coarseGraph.xadj[u]; e < coarseGraph.xadj[u + 1]; ++e) {
            int v = coarseGraph.adjncy[e];
            if (u < v) {  // Write each edge once
                outFile << u << " " << v << "\n";
            }
        }
    }
    outFile.close();
    
    // Load into SpectralPartitioner
    spectral.loadGraph(tempFile, graphID);
    
    // Determine k using eigengap if not specified
    int k = numPartitions;
    if (k == 0) {
        k = spectral.computeOptimalK(config.maxK);
        multilevel_logger.log("Eigengap heuristic selected k=" + std::to_string(k), "info");
        eigenvalues = spectral.getEigenvalues();
    }
    
    // Run spectral partitioning
    vector<int> labels = spectral.partition(k);
    
    // Clean up temp file
    std::remove(tempFile.c_str());
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    multilevel_logger.log("Initial partitioning time: " + std::to_string(duration.count()) + " ms", "info");
    
    return labels;
}

vector<int> MultilevelSpectralPartitioner::projectPartitions(const vector<int> &coarseLabels, 
                                                             const vector<int> &fine2coarse) {
    vector<int> fineLabels(fine2coarse.size());
    
    for (size_t i = 0; i < fine2coarse.size(); ++i) {
        fineLabels[i] = coarseLabels[fine2coarse[i]];
    }
    
    return fineLabels;
}

void MultilevelSpectralPartitioner::refinePartitions(const CoarseGraph &graph, vector<int> &labels) {
    // Simple boundary refinement using Kernighan-Lin style moves
    int n = graph.numVertices;
    int numPartitions = *std::max_element(labels.begin(), labels.end()) + 1;
    
    // Compute partition sizes
    vector<int> partitionSizes(numPartitions, 0);
    for (int label : labels) {
        partitionSizes[label]++;
    }
    
    int avgSize = n / numPartitions;
    bool improved = true;
    int iterations = 0;
    const int maxIterations = 5;
    
    while (improved && iterations < maxIterations) {
        improved = false;
        iterations++;
        
        for (int u = 0; u < n; ++u) {
            int currentPart = labels[u];
            int externalDegree = 0;
            int internalDegree = 0;
            
            // Count internal vs external edges
            vector<int> externalCount(numPartitions, 0);
            for (int e = graph.xadj[u]; e < graph.xadj[u + 1]; ++e) {
                int v = graph.adjncy[e];
                if (labels[v] == currentPart) {
                    internalDegree++;
                } else {
                    externalDegree++;
                    externalCount[labels[v]]++;
                }
            }
            
            // Try to move to partition with most external connections
            if (externalDegree > internalDegree) {
                int bestPart = currentPart;
                int maxExternal = 0;
                
                for (int p = 0; p < numPartitions; ++p) {
                    if (p != currentPart && externalCount[p] > maxExternal) {
                        // Check balance constraint
                        double imbalance = (double)(partitionSizes[p] + 1) / avgSize;
                        if (imbalance <= config.balanceEpsilon) {
                            maxExternal = externalCount[p];
                            bestPart = p;
                        }
                    }
                }
                
                if (bestPart != currentPart) {
                    labels[u] = bestPart;
                    partitionSizes[currentPart]--;
                    partitionSizes[bestPart]++;
                    improved = true;
                }
            }
        }
    }
    
    multilevel_logger.log("Refinement: " + std::to_string(iterations) + " iterations", "info");
}

std::map<string, double> MultilevelSpectralPartitioner::computeMetrics(const CoarseGraph &graph, 
                                                                       const vector<int> &labels, 
                                                                       int numPartitions) {
    std::map<string, double> metrics;
    
    // Edge cut
    int edgeCut = 0;
    for (int u = 0; u < graph.numVertices; ++u) {
        for (int e = graph.xadj[u]; e < graph.xadj[u + 1]; ++e) {
            int v = graph.adjncy[e];
            if (labels[u] != labels[v]) {
                edgeCut++;
            }
        }
    }
    metrics["edgeCut"] = edgeCut / 2.0;  // Each edge counted twice
    
    // Balance
    vector<int> partitionSizes(numPartitions, 0);
    for (int label : labels) {
        partitionSizes[label]++;
    }
    
    int avgSize = graph.numVertices / numPartitions;
    double maxImbalance = 0.0;
    for (int size : partitionSizes) {
        double imbalance = (double)size / avgSize;
        maxImbalance = std::max(maxImbalance, std::abs(imbalance - 1.0));
    }
    metrics["maxImbalance"] = maxImbalance;
    
    return metrics;
}

vector<int> MultilevelSpectralPartitioner::partition(int numPartitions) {
    multilevel_logger.log("Starting multilevel spectral partitioning", "info");
    
    auto totalStart = std::chrono::high_resolution_clock::now();
    
    // Phase 1: Coarsening
    CoarseGraph coarsest = buildHierarchy();
    
    // Phase 2: Initial partitioning on coarsest graph
    vector<int> labels = initialPartition(coarsest, numPartitions);
    
    // Phase 3: Uncoarsening with refinement
    multilevel_logger.log("Uncoarsening and refinement", "info");
    auto refineStart = std::chrono::high_resolution_clock::now();
    
    for (int level = coarsenLevels - 1; level >= 0; --level) {
        // Project to finer level
        labels = projectPartitions(labels, fine2coarseMappings[level]);
        
        // Refine
        refinePartitions(graphHierarchy[level], labels);
        
        // Compute metrics
        int numParts = *std::max_element(labels.begin(), labels.end()) + 1;
        auto metrics = computeMetrics(graphHierarchy[level], labels, numParts);
        multilevel_logger.log("Level " + std::to_string(level) + ": edgeCut=" + 
                             std::to_string((int)metrics["edgeCut"]) + 
                             ", imbalance=" + std::to_string(metrics["maxImbalance"]), "info");
    }
    
    auto refineEnd = std::chrono::high_resolution_clock::now();
    auto refineDuration = std::chrono::duration_cast<std::chrono::milliseconds>(refineEnd - refineStart);
    multilevel_logger.log("Uncoarsening time: " + std::to_string(refineDuration.count()) + " ms", "info");
    
    // Final metrics
    int numParts = *std::max_element(labels.begin(), labels.end()) + 1;
    auto finalMetrics = computeMetrics(graphHierarchy[0], labels, numParts);
    multilevel_logger.log("Final: k=" + std::to_string(numParts) + 
                         ", edgeCut=" + std::to_string((int)finalMetrics["edgeCut"]) + 
                         ", imbalance=" + std::to_string(finalMetrics["maxImbalance"]), "info");
    
    auto totalEnd = std::chrono::high_resolution_clock::now();
    auto totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(totalEnd - totalStart);
    multilevel_logger.log("Total partitioning time: " + std::to_string(totalDuration.count()) + " ms", "info");
    
    return labels;
}

std::map<int, std::string> MultilevelSpectralPartitioner::savePartitions(const vector<int> &partitionAssignment) {
    multilevel_logger.log("Saving partition files with local/central store separation", "info");

    int numPartitions = *std::max_element(partitionAssignment.begin(), partitionAssignment.end()) + 1;
    std::map<int, std::string> partitionFiles;
    
    // Maps for local and central store edges
    std::map<int, std::map<int, vector<int>>> localStoreMap;  // partition -> (src -> [dst])
    std::map<int, std::map<int, vector<int>>> centralStoreMap; // partition -> (src -> [dst])
    
    // Statistics
    vector<int> localEdgeCounts(numPartitions, 0);
    vector<int> centralEdgeCounts(numPartitions, 0);
    vector<std::set<int>> centralVertices(numPartitions);  // Track boundary vertices
    
    // Separate edges into local store (both vertices in same partition) 
    // and central store (vertices in different partitions)
    for (const auto &entry : adjList) {
        int u = entry.first;
        int partU = partitionAssignment[u];

        for (int v : entry.second) {
            int partV = partitionAssignment[v];

            if (partU == partV) {
                // Local store edge: both vertices in same partition
                if (u < v) {  // Avoid duplicates
                    localStoreMap[partU][u].push_back(v);
                    localEdgeCounts[partU]++;
                }
            } else {
                // Central store edge: vertices in different partitions
                // Add to source vertex's partition's central store
                centralStoreMap[partU][u].push_back(v);
                centralEdgeCounts[partU]++;
                centralVertices[partU].insert(v);  // Track boundary vertices
            }
        }
    }
    
    // Write local store files (partition-local edges)
    for (int p = 0; p < numPartitions; ++p) {
        string filename = outputFilePath + "/" + std::to_string(graphID) + "_partition_" + std::to_string(p) + ".txt";
        std::ofstream outFile(filename);
        
        const auto &localEdges = localStoreMap[p];
        for (const auto &entry : localEdges) {
            int u = entry.first;
            int originalU = reverseVertexMap[u];
            
            for (int v : entry.second) {
                int originalV = reverseVertexMap[v];
                outFile << originalU << " " << originalV << "\n";
            }
        }
        
        outFile.close();
        partitionFiles[p] = filename;
    }
    
    // Write central store files (boundary/cross-partition edges)
    for (int p = 0; p < numPartitions; ++p) {
        string filename = outputFilePath + "/" + std::to_string(graphID) + "_centralstore_" + std::to_string(p) + ".txt";
        std::ofstream outFile(filename);
        
        const auto &centralEdges = centralStoreMap[p];
        for (const auto &entry : centralEdges) {
            int u = entry.first;
            int originalU = reverseVertexMap[u];
            
            for (int v : entry.second) {
                int originalV = reverseVertexMap[v];
                outFile << originalU << " " << originalV << "\n";
            }
        }
        
        outFile.close();
    }
    
    // Log statistics
    int totalLocal = std::accumulate(localEdgeCounts.begin(), localEdgeCounts.end(), 0);
    int totalCentral = std::accumulate(centralEdgeCounts.begin(), centralEdgeCounts.end(), 0);
    int totalBoundaryVertices = 0;
    for (const auto &vset : centralVertices) {
        totalBoundaryVertices += vset.size();
    }
    
    multilevel_logger.log("Partition statistics:", "info");
    multilevel_logger.log("  Total local edges: " + std::to_string(totalLocal), "info");
    multilevel_logger.log("  Total central store edges: " + std::to_string(totalCentral), "info");
    multilevel_logger.log("  Total boundary vertices: " + std::to_string(totalBoundaryVertices), "info");
    multilevel_logger.log("  Edge cut ratio: " + 
                         std::to_string((double)totalCentral / (totalLocal + totalCentral)), "info");
    
    for (int p = 0; p < numPartitions; ++p) {
        multilevel_logger.log("  Partition " + std::to_string(p) + ": " +
                             std::to_string(localEdgeCounts[p]) + " local, " +
                             std::to_string(centralEdgeCounts[p]) + " central, " +
                             std::to_string(centralVertices[p].size()) + " boundary vertices", "info");
    }

    multilevel_logger.log("Saved " + std::to_string(numPartitions) + " partition files with central stores", "info");
    return partitionFiles;
}
