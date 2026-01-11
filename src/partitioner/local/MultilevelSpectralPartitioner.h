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

#ifndef JASMINEGRAPH_MULTILEVELSPECTRALPARTITIONER_H
#define JASMINEGRAPH_MULTILEVELSPECTRALPARTITIONER_H

#include <algorithm>
#include <cmath>
#include <vector>
#include <map>
#include <unordered_map>
#include <string>

#include "../../metadb/SQLiteDBInterface.h"
#include "SpectralPartitioner.h"

using std::string;
using std::vector;

/**
 * Configuration for multilevel spectral partitioning
 */
struct MultilevelConfig {
    int coarseLimit = 20000;          // Stop coarsening when graph size < this
    int maxK = 16;                     // Maximum partitions to consider for eigengap
    double balanceEpsilon = 1.03;      // Balance tolerance (within 3%)
    int maxCoarsenLevels = 10;         // Maximum coarsening iterations
    bool useParallelMatching = true;   // Enable parallel heavy edge matching
    bool useBalancedClustering = true; // Use balanced k-means instead of standard
};

/**
 * Coarse graph representation for multilevel hierarchy
 */
struct CoarseGraph {
    int numVertices;
    vector<int> xadj;          // CSR row pointers
    vector<int> adjncy;        // CSR column indices
    vector<int> vertexWeights; // Vertex weights (for balanced partitioning)
    
    CoarseGraph() : numVertices(0) {}
    CoarseGraph(int n) : numVertices(n), xadj(n+1, 0) {}
};

/**
 * Multilevel Spectral Graph Partitioner
 * 
 * Combines three powerful techniques:
 * 1. Multilevel coarsening: Reduces graph size progressively using heavy-edge matching
 * 2. Spectral partitioning: Uses eigengap heuristic + eigenvector clustering on coarsest graph
 * 3. Refinement: Projects partitions back through hierarchy
 * 
 * Advantages over basic spectral partitioning:
 * - Handles very large graphs (millions of vertices)
 * - Faster computation (coarsening reduces eigenvalue problem size)
 * - Better partition quality (refinement at each level)
 * - Automatic k selection via eigengap heuristic
 * - Balanced partitions (within configurable tolerance)
 */
class MultilevelSpectralPartitioner {
 public:
    MultilevelSpectralPartitioner(SQLiteDBInterface *sqlite, const MultilevelConfig &config = MultilevelConfig());

    /**
     * Load graph from edge list file
     * @param inputFilePath Path to edge list file
     * @param graphID Graph identifier
     */
    void loadGraph(const string &inputFilePath, int graphID);

    /**
     * Partition graph using multilevel spectral clustering
     * 
     * Process:
     * 1. Coarsening phase: repeatedly match and collapse heavy edges
     * 2. Initial partitioning: use spectral + eigengap on coarsest graph
     * 3. Uncoarsening phase: project and refine partitions
     * 
     * @param numPartitions Number of partitions (0 = auto-detect via eigengap)
     * @return Partition assignment for each vertex
     */
    vector<int> partition(int numPartitions = 0);

    /**
     * Save partitioned graph to files
     * @param partitionAssignment Partition assignment for each vertex
     * @return Map of partition files
     */
    std::map<int, std::string> savePartitions(const vector<int> &partitionAssignment);

    // Get graph statistics
    int getVertexCount() const { return vertexCount; }
    int getEdgeCount() const { return edgeCount; }
    int getCoarsenLevels() const { return coarsenLevels; }
    vector<double> getEigenvalues() const { return eigenvalues; }

 private:
    SQLiteDBInterface *sqlite;
    MultilevelConfig config;
    int graphID;
    int vertexCount;
    int edgeCount;
    int coarsenLevels;
    string outputFilePath;

    // Original graph storage
    std::unordered_map<int, vector<int>> adjList;
    std::map<int, int> vertexIdMap;  // Original ID -> Sequential ID
    vector<int> reverseVertexMap;    // Sequential ID -> Original ID

    // Multilevel hierarchy
    vector<CoarseGraph> graphHierarchy;
    vector<vector<int>> fine2coarseMappings;  // Mapping at each level
    
    // Eigenvalue info from coarsest level
    vector<double> eigenvalues;

    /**
     * Coarsening phase: Build graph hierarchy
     * Repeatedly applies heavy-edge matching until coarse limit reached
     * @return Coarsest graph
     */
    CoarseGraph buildHierarchy();

    /**
     * Heavy edge matching with optional OpenMP parallelization
     * Greedily matches vertices to their heaviest neighbor
     * @param graph Current graph
     * @param match Output: match[i] = j means i matched with j
     */
    void heavyEdgeMatching(const CoarseGraph &graph, vector<int> &match);

    /**
     * Coarsen graph based on matching
     * Collapses matched vertices into super-vertices
     * @param graph Fine graph
     * @param match Matching from heavyEdgeMatching
     * @param fine2coarse Output: mapping from fine to coarse vertices
     * @return Coarsened graph
     */
    CoarseGraph coarsenGraph(const CoarseGraph &graph, const vector<int> &match, vector<int> &fine2coarse);

    /**
     * Initial partitioning on coarsest graph
     * Uses spectral clustering with eigengap heuristic
     * @param coarseGraph Coarsest graph from hierarchy
     * @param numPartitions Number of partitions (0 = auto via eigengap)
     * @return Partition labels for coarse vertices
     */
    vector<int> initialPartition(const CoarseGraph &coarseGraph, int numPartitions);

    /**
     * Uncoarsening phase: Project partitions back through hierarchy
     * Projects from coarse to fine level with optional refinement
     * @param coarseLabels Partition labels at coarse level
     * @param fine2coarse Mapping from fine to coarse
     * @return Partition labels at fine level
     */
    vector<int> projectPartitions(const vector<int> &coarseLabels, const vector<int> &fine2coarse);

    /**
     * Refine partitions using local improvements
     * Moves vertices to improve cut quality and balance
     * @param graph Current graph
     * @param labels Current partition labels
     */
    void refinePartitions(const CoarseGraph &graph, vector<int> &labels);

    /**
     * Compute partition balance and quality metrics
     * @param graph Current graph
     * @param labels Partition labels
     * @param numPartitions Number of partitions
     * @return Map with metrics: "edgeCut", "maxImbalance"
     */
    std::map<string, double> computeMetrics(const CoarseGraph &graph, const vector<int> &labels, int numPartitions);

    /**
     * Convert adjacency list to CoarseGraph format
     * @return Initial CoarseGraph
     */
    CoarseGraph convertToCoarseGraph();

    /**
     * Convert CoarseGraph to format usable by SpectralPartitioner
     * Creates temporary adjacency list representation
     * @param graph CoarseGraph to convert
     * @return Adjacency list map
     */
    std::unordered_map<int, vector<int>> convertToAdjList(const CoarseGraph &graph);
};

#endif  // JASMINEGRAPH_MULTILEVELSPECTRALPARTITIONER_H
