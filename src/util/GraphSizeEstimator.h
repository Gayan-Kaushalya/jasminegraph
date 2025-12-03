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

#ifndef JASMINEGRAPH_GRAPHSIZEESTIMATOR_H
#define JASMINEGRAPH_GRAPHSIZEESTIMATOR_H

#include <string>
#include <fstream>

using namespace std;

/**
 * Utility class for estimating graph size in memory
 */
class GraphSizeEstimator {
public:
    /**
     * Estimate graph size from file path
     * @param filePath Path to the graph file
     * @return Estimated size in bytes
     */
    static long estimateFromFile(const string& filePath);
    
    /**
     * Estimate graph size from vertex and edge counts
     * @param vertexCount Number of vertices
     * @param edgeCount Number of edges
     * @param hasFeatures Whether the graph has node features
     * @param featureCount Number of features per vertex (if applicable)
     * @return Estimated size in bytes
     */
    static long estimateFromCounts(long vertexCount, long edgeCount, bool hasFeatures = false, int featureCount = 0);
    
    /**
     * Get file size in bytes
     * @param filePath Path to the file
     * @return File size in bytes
     */
    static long getFileSize(const string& filePath);
    
    /**
     * Count lines in a file (estimate edge count)
     * @param filePath Path to the graph file
     * @return Number of lines (edges)
     */
    static long countLinesInFile(const string& filePath);
    
    /**
     * Parse graph file to get vertex and edge counts
     * @param filePath Path to the graph file
     * @param vertexCount Reference to store vertex count
     * @param edgeCount Reference to store edge count
     * @return True if successful
     */
    static bool parseGraphFile(const string& filePath, long& vertexCount, long& edgeCount);

private:
    /**
     * Calculate memory overhead for graph structures
     * @param baseSize Base memory size
     * @return Overhead in bytes
     */
    static long calculateOverhead(long baseSize);
};

#endif //JASMINEGRAPH_GRAPHSIZEESTIMATOR_H