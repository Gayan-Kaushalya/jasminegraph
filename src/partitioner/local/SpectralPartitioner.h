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

#ifndef JASMINEGRAPH_SPECTRALPARTITIONER_H
#define JASMINEGRAPH_SPECTRALPARTITIONER_H

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iostream>
#include <map>
#include <numeric>
#include <string>
#include <unordered_map>
#include <vector>

// Try to use Eigen library for fast eigenvalue computation
#ifdef __has_include
#  if __has_include(<Eigen/Sparse>)
#    define HAS_EIGEN 1
#    include <Eigen/Sparse>
#    include <Eigen/Eigenvalues>
#  endif
#endif

#include "../../metadb/SQLiteDBInterface.h"
#include "../../util/Utils.h"

using std::string;
using std::vector;

/**
 * Sparse matrix representation using Compressed Sparse Row (CSR) format
 * Memory-efficient for large graphs: O(n + edges) instead of O(n^2)
 */
struct SparseMatrix {
    vector<double> values;       // Non-zero values
    vector<int> colIndices;      // Column indices
    vector<int> rowPointers;     // Row start positions
    int numRows;
    int numCols;

    SparseMatrix(int rows, int cols) : numRows(rows), numCols(cols) { rowPointers.resize(rows + 1, 0); }

    // Sparse matrix-vector multiplication: y = A * x
    void multiply(const vector<double> &x, vector<double> &y) const;

    // Add edge to sparse matrix (for building Laplacian)
    void addEdge(int row, int col, double value);

    // Finalize the matrix structure after all edges are added
    void finalize();
};

/**
 * Efficient Spectral Graph Partitioner
 * Uses:
 * - Sparse matrix representations (CSR format)
 * - Power iteration for computing eigenvectors
 * - Eigengap heuristic for optimal k selection
 * - Normalized graph Laplacian for better results
 */
class SpectralPartitioner {
 public:
    SpectralPartitioner(SQLiteDBInterface *sqlite);

    /**
     * Load graph from edge list file
     * @param inputFilePath Path to edge list file
     * @param graphID Graph identifier
     */
    void loadGraph(const string &inputFilePath, int graphID);

    /**
     * Compute eigengap to determine optimal number of partitions
     * Eigengap heuristic: finds largest gap between consecutive eigenvalues
     * @param maxK Maximum number of eigenvalues to compute
     * @return Optimal number of clusters (k)
     */
    int computeOptimalK(int maxK = 10);

    /**
     * Partition graph using spectral clustering
     * @param numPartitions Number of partitions (uses eigengap if 0)
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
    vector<double> getEigenvalues() const { return eigenvalues; }

 private:
    SQLiteDBInterface *sqlite;
    int graphID;
    int vertexCount;
    int edgeCount;
    string outputFilePath;

    // Graph storage: adjacency list
    std::unordered_map<int, vector<int>> adjList;
    std::map<int, int> vertexIdMap;  // Original ID -> Sequential ID
    vector<int> reverseVertexMap;    // Sequential ID -> Original ID

    // Computed eigenvalues and eigenvectors
    vector<double> eigenvalues;
    vector<vector<double>> eigenvectors;

    /**
     * Build normalized graph Laplacian: L_norm = I - D^(-1/2) * A * D^(-1/2)
     * where D is degree matrix, A is adjacency matrix
     * More memory-efficient than constructing full dense matrices
     */
    SparseMatrix buildNormalizedLaplacian();

    /**
     * Compute k smallest eigenvectors using inverse power iteration
     * Much faster than full eigendecomposition: O(k*n*edges) vs O(n^3)
     * @param laplacian Normalized graph Laplacian
     * @param k Number of eigenvectors to compute
     */
    void computeEigenvectors(const SparseMatrix &laplacian, int k);

#ifdef HAS_EIGEN
    /**
     * Fast eigenvalue computation using Eigen library (10-50x faster)
     * Uses ARPACK-based sparse eigensolver
     * @param laplacian Normalized Laplacian matrix
     * @param k Number of eigenvectors to compute
     */
    void computeEigenvectorsEigen(const SparseMatrix &laplacian, int k);
#endif

    /**
     * Inverse power iteration for computing smallest eigenvector
     * Iteratively refines estimate until convergence
     * @param matrix Sparse matrix
     * @param maxIter Maximum iterations
     * @param tolerance Convergence tolerance
     * @return Eigenvector (normalized)
     */
    vector<double> inversePowerIteration(const SparseMatrix &matrix, int maxIter = 100, double tolerance = 1e-6);

    /**
     * Deflate matrix to remove already-computed eigenvector
     * Allows computing next smallest eigenvector
     * @param matrix Original matrix
     * @param eigenvector Previously computed eigenvector
     * @param eigenvalue Corresponding eigenvalue
     * @return Deflated matrix
     */
    SparseMatrix deflate(const SparseMatrix &matrix, const vector<double> &eigenvector, double eigenvalue);

    /**
     * K-means clustering on eigenvector matrix
     * Standard k-means with multiple random initializations
     * @param k Number of clusters
     * @param maxIter Maximum iterations
     * @return Cluster assignments
     */
    vector<int> kMeansClustering(int k, int maxIter = 100);

    /**
     * Compute Rayleigh quotient to estimate eigenvalue
     * @param matrix Sparse matrix
     * @param vector Eigenvector estimate
     * @return Eigenvalue estimate
     */
    double rayleighQuotient(const SparseMatrix &matrix, const vector<double> &vector);

    // Utility functions
    double vectorNorm(const vector<double> &v);
    void normalizeVector(vector<double> &v);
    double dotProduct(const vector<double> &a, const vector<double> &b);
    vector<double> vectorSubtract(const vector<double> &a, const vector<double> &b);
    vector<double> scalarMultiply(const vector<double> &v, double scalar);
};

#endif  // JASMINEGRAPH_SPECTRALPARTITIONER_H
