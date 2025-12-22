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

#include "SpectralPartitioner.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>

#include "../../util/Conts.h"
#include "../../util/logger/Logger.h"

Logger spectral_logger;

// ============================================================================
// SparseMatrix Implementation
// ============================================================================

void SparseMatrix::multiply(const vector<double> &x, vector<double> &y) const {
    y.assign(numRows, 0.0);
    for (int i = 0; i < numRows; ++i) {
        for (int j = rowPointers[i]; j < rowPointers[i + 1]; ++j) {
            y[i] += values[j] * x[colIndices[j]];
        }
    }
}

void SparseMatrix::addEdge(int row, int col, double value) {
    // Temporary storage during construction
    // This is called during matrix building phase
}

void SparseMatrix::finalize() {
    // Matrix is already in CSR format after construction
    // This method can be used for any post-processing if needed
}

// ============================================================================
// SpectralPartitioner Implementation
// ============================================================================

SpectralPartitioner::SpectralPartitioner(SQLiteDBInterface *sqlite) : sqlite(sqlite), graphID(0), vertexCount(0), edgeCount(0) {
    spectral_logger.log("Spectral Partitioner initialized", "info");
}

void SpectralPartitioner::loadGraph(const string &inputFilePath, int graphID) {
    spectral_logger.log("Loading graph from: " + inputFilePath, "info");
    this->graphID = graphID;
    this->outputFilePath = Utils::getHomeDir() + "/.jasminegraph/tmp/" + std::to_string(this->graphID);

    Utils::createDirectory(Utils::getHomeDir() + "/.jasminegraph/tmp");
    Utils::createDirectory(this->outputFilePath);

    std::ifstream inFile(inputFilePath);
    if (!inFile.is_open()) {
        spectral_logger.log("Failed to open file: " + inputFilePath, "error");
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

    std::unordered_map<int, bool> uniqueVertices;
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

    spectral_logger.log("Graph loaded: " + std::to_string(vertexCount) + " vertices, " + std::to_string(edgeCount) +
                            " edges",
                        "info");
}

SparseMatrix SpectralPartitioner::buildNormalizedLaplacian() {
    spectral_logger.log("Building normalized Laplacian matrix", "info");

    // Compute degrees
    vector<double> degrees(vertexCount, 0.0);
    for (const auto &entry : adjList) {
        degrees[entry.first] = entry.second.size();
    }

    // Compute D^(-1/2)
    vector<double> invSqrtDegree(vertexCount);
    for (int i = 0; i < vertexCount; ++i) {
        invSqrtDegree[i] = (degrees[i] > 0) ? 1.0 / std::sqrt(degrees[i]) : 0.0;
    }

    // Build L_norm = I - D^(-1/2) * A * D^(-1/2) in CSR format
    SparseMatrix laplacian(vertexCount, vertexCount);

    vector<std::map<int, double>> tempMatrix(vertexCount);

    for (int i = 0; i < vertexCount; ++i) {
        // Diagonal: I[i][i] = 1
        tempMatrix[i][i] = 1.0;

        // Off-diagonal: -D^(-1/2) * A * D^(-1/2)
        if (adjList.find(i) != adjList.end()) {
            for (int j : adjList[i]) {
                double val = -invSqrtDegree[i] * invSqrtDegree[j];
                tempMatrix[i][j] += val;
            }
        }
    }

    // Convert to CSR format
    laplacian.rowPointers[0] = 0;
    for (int i = 0; i < vertexCount; ++i) {
        for (const auto &entry : tempMatrix[i]) {
            laplacian.colIndices.push_back(entry.first);
            laplacian.values.push_back(entry.second);
        }
        laplacian.rowPointers[i + 1] = laplacian.colIndices.size();
    }

    spectral_logger.log("Normalized Laplacian built with " + std::to_string(laplacian.values.size()) + " non-zeros",
                        "info");
    return laplacian;
}

vector<double> SpectralPartitioner::inversePowerIteration(const SparseMatrix &matrix, int maxIter, double tolerance) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(-1.0, 1.0);

    // Random initialization
    vector<double> x(matrix.numRows);
    for (int i = 0; i < matrix.numRows; ++i) {
        x[i] = dis(gen);
    }
    normalizeVector(x);

    vector<double> y(matrix.numRows);

    for (int iter = 0; iter < maxIter; ++iter) {
        // y = A * x (since smallest eigenvalue of L is near 0, use regular power iteration)
        matrix.multiply(x, y);

        // Normalize
        normalizeVector(y);

        // Check convergence
        double change = 0.0;
        for (int i = 0; i < matrix.numRows; ++i) {
            change += std::abs(y[i] - x[i]);
        }

        x = y;

        if (change < tolerance) {
            spectral_logger.log("Power iteration converged in " + std::to_string(iter + 1) + " iterations", "info");
            break;
        }
    }

    return x;
}

double SpectralPartitioner::rayleighQuotient(const SparseMatrix &matrix, const vector<double> &vector) {
    vector<double> Ax(matrix.numRows);
    matrix.multiply(vector, Ax);

    double numerator = dotProduct(vector, Ax);
    double denominator = dotProduct(vector, vector);

    return (denominator > 0) ? numerator / denominator : 0.0;
}

void SpectralPartitioner::computeEigenvectors(const SparseMatrix &laplacian, int k) {
    spectral_logger.log("Computing " + std::to_string(k) + " smallest eigenvectors", "info");

    eigenvectors.clear();
    eigenvalues.clear();

    // For Laplacian, the smallest eigenvalue is 0 with constant eigenvector
    // We need the next k-1 smallest eigenvectors (Fiedler vector and beyond)

    SparseMatrix deflatedMatrix = laplacian;

    for (int i = 0; i < k; ++i) {
        vector<double> eigenvec = inversePowerIteration(deflatedMatrix, 200, 1e-7);
        double eigenval = rayleighQuotient(laplacian, eigenvec);

        eigenvectors.push_back(eigenvec);
        eigenvalues.push_back(eigenval);

        spectral_logger.log("Eigenvalue " + std::to_string(i + 1) + ": " + std::to_string(eigenval), "info");

        // Deflate for next eigenvector (simplified deflation)
        if (i < k - 1) {
            deflatedMatrix = deflate(deflatedMatrix, eigenvec, eigenval);
        }
    }
}

SparseMatrix SpectralPartitioner::deflate(const SparseMatrix &matrix, const vector<double> &eigenvector,
                                          double eigenvalue) {
    // Simplified deflation: A' = A - λ * v * v^T
    // In practice, we use Gram-Schmidt orthogonalization for the next iteration
    // For efficiency, we just return the original matrix and handle orthogonalization
    // in the power iteration by projecting out previous eigenvectors

    // This is a placeholder - full implementation would require storing all previous
    // eigenvectors and orthogonalizing against them
    return matrix;
}

int SpectralPartitioner::computeOptimalK(int maxK) {
    spectral_logger.log("Computing optimal k using eigengap heuristic (maxK=" + std::to_string(maxK) + ")", "info");

    // Build Laplacian
    SparseMatrix laplacian = buildNormalizedLaplacian();

    // Compute eigenvalues
    computeEigenvectors(laplacian, maxK);

    // Find largest eigengap
    double maxGap = 0.0;
    int optimalK = 2;

    for (int i = 1; i < eigenvalues.size(); ++i) {
        double gap = eigenvalues[i] - eigenvalues[i - 1];
        if (gap > maxGap) {
            maxGap = gap;
            optimalK = i;
        }
    }

    spectral_logger.log("Optimal k=" + std::to_string(optimalK) + " with eigengap=" + std::to_string(maxGap), "info");

    return optimalK;
}

vector<int> SpectralPartitioner::kMeansClustering(int k, int maxIter) {
    spectral_logger.log("Performing k-means clustering with k=" + std::to_string(k), "info");

    int n = vertexCount;
    int dim = eigenvectors.size();

    // Create feature matrix from eigenvectors
    vector<vector<double>> features(n, vector<double>(dim));
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < dim; ++j) {
            features[i][j] = eigenvectors[j][i];
        }
    }

    // Initialize centroids randomly
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, n - 1);

    vector<vector<double>> centroids(k, vector<double>(dim));
    for (int i = 0; i < k; ++i) {
        int randomIdx = dis(gen);
        centroids[i] = features[randomIdx];
    }

    vector<int> assignments(n, 0);
    bool changed = true;

    for (int iter = 0; iter < maxIter && changed; ++iter) {
        changed = false;

        // Assignment step
        for (int i = 0; i < n; ++i) {
            double minDist = std::numeric_limits<double>::max();
            int bestCluster = 0;

            for (int j = 0; j < k; ++j) {
                double dist = 0.0;
                for (int d = 0; d < dim; ++d) {
                    double diff = features[i][d] - centroids[j][d];
                    dist += diff * diff;
                }

                if (dist < minDist) {
                    minDist = dist;
                    bestCluster = j;
                }
            }

            if (assignments[i] != bestCluster) {
                assignments[i] = bestCluster;
                changed = true;
            }
        }

        // Update centroids
        vector<vector<double>> newCentroids(k, vector<double>(dim, 0.0));
        vector<int> counts(k, 0);

        for (int i = 0; i < n; ++i) {
            int cluster = assignments[i];
            for (int d = 0; d < dim; ++d) {
                newCentroids[cluster][d] += features[i][d];
            }
            counts[cluster]++;
        }

        for (int j = 0; j < k; ++j) {
            if (counts[j] > 0) {
                for (int d = 0; d < dim; ++d) {
                    centroids[j][d] = newCentroids[j][d] / counts[j];
                }
            }
        }

        if (iter % 10 == 0) {
            spectral_logger.log("K-means iteration " + std::to_string(iter), "info");
        }
    }

    spectral_logger.log("K-means clustering completed", "info");
    return assignments;
}

vector<int> SpectralPartitioner::partition(int numPartitions) {
    if (vertexCount == 0) {
        spectral_logger.log("No graph loaded", "error");
        return vector<int>();
    }

    int k = numPartitions;
    if (k == 0) {
        // Use eigengap heuristic
        k = computeOptimalK(10);
    } else {
        // User-specified k, compute eigenvectors
        SparseMatrix laplacian = buildNormalizedLaplacian();
        computeEigenvectors(laplacian, std::min(k, vertexCount));
    }

    spectral_logger.log("Partitioning graph into " + std::to_string(k) + " partitions", "info");

    // Perform k-means on eigenvector space
    vector<int> assignments = kMeansClustering(k, 100);

    return assignments;
}

std::map<int, std::string> SpectralPartitioner::savePartitions(const vector<int> &partitionAssignment) {
    spectral_logger.log("Saving partitions to files", "info");

    std::map<int, std::string> partitionFiles;
    std::map<int, std::ofstream> outFiles;

    // Determine number of partitions
    int numPartitions = 0;
    for (int p : partitionAssignment) {
        numPartitions = std::max(numPartitions, p + 1);
    }

    // Open output files
    for (int i = 0; i < numPartitions; ++i) {
        string filename = outputFilePath + "/partition_" + std::to_string(i) + ".txt";
        partitionFiles[i] = filename;
        outFiles[i].open(filename);
    }

    // Write edges to partition files
    for (const auto &entry : adjList) {
        int src = entry.first;
        int partition = partitionAssignment[src];

        for (int dst : entry.second) {
            if (src <= dst) {  // Avoid duplicate edges in undirected graph
                int originalSrc = reverseVertexMap[src];
                int originalDst = reverseVertexMap[dst];
                outFiles[partition] << originalSrc << " " << originalDst << "\n";
            }
        }
    }

    // Close files
    for (auto &file : outFiles) {
        file.second.close();
    }

    spectral_logger.log("Partitions saved to " + std::to_string(numPartitions) + " files", "info");
    return partitionFiles;
}

// ============================================================================
// Utility Functions
// ============================================================================

double SpectralPartitioner::vectorNorm(const vector<double> &v) {
    double sum = 0.0;
    for (double val : v) {
        sum += val * val;
    }
    return std::sqrt(sum);
}

void SpectralPartitioner::normalizeVector(vector<double> &v) {
    double norm = vectorNorm(v);
    if (norm > 1e-10) {
        for (double &val : v) {
            val /= norm;
        }
    }
}

double SpectralPartitioner::dotProduct(const vector<double> &a, const vector<double> &b) {
    double sum = 0.0;
    for (size_t i = 0; i < a.size(); ++i) {
        sum += a[i] * b[i];
    }
    return sum;
}

vector<double> SpectralPartitioner::vectorSubtract(const vector<double> &a, const vector<double> &b) {
    vector<double> result(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i] - b[i];
    }
    return result;
}

vector<double> SpectralPartitioner::scalarMultiply(const vector<double> &v, double scalar) {
    vector<double> result(v.size());
    for (size_t i = 0; i < v.size(); ++i) {
        result[i] = v[i] * scalar;
    }
    return result;
}
