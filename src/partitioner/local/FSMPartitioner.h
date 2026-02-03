/**
Copyright 2019 JasmineGraph Team
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

#ifndef JASMINEGRAPH_FSMPARTITIONER_H
#define JASMINEGRAPH_FSMPARTITIONER_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include "../../metadb/SQLiteDBInterface.h"

using std::string;

/**
 * FSMPartitioner - Integration wrapper for FSM graph partitioning framework
 * 
 * This class provides an interface to use various partitioning algorithms from
 * the FSM framework (Fast Streaming Methods) within JasmineGraph.
 * 
 * Supported partitioning methods:
 * - hep: High-degree Edge Partitioning
 * - ne: Neighbor Expansion  
 * - hdrf: High-Degree Replicated First
 * - hybrid: Hybrid partitioning approach
 * - ebv: Edge-Balanced Vertex-cut
 * - dbh: Degree-Based Hashing
 * - rand: Random partitioning
 * - fennel: Fennel streaming partitioner
 * - bpart: Balanced partitioning
 * - hybridbl: Hybrid with balance
 * - fsm_ne: FSM with NE (multi-level)
 * - fsm_hep: FSM with HEP (multi-level)
 */
class FSMPartitioner {
 public:
    /**
     * Constructor
     * @param sqlite Database interface for storing partition metadata
     */
    explicit FSMPartitioner(SQLiteDBInterface *sqlite);

    /**
     * Partition a graph using FSM framework
     * 
     * @param inputFilePath Path to the input graph file (edgelist format)
     * @param graphID The JasmineGraph graph identifier
     * @param partitionCount Number of partitions to create
     * @param method Partitioning method (hep, ne, hdrf, hybrid, ebv, dbh, rand, fennel, bpart, hybridbl, fsm_ne, fsm_hep)
     * @return Map of partition files created (partitionID -> filepath)
     */
    std::map<int, std::string> partition(const string& inputFilePath, 
                                         int graphID,
                                         int partitionCount,
                                         const string& method = "hep");

    /**
     * Partition a graph with custom FSM parameters
     * 
     * @param inputFilePath Path to the input graph file
     * @param graphID The JasmineGraph graph identifier
     * @param partitionCount Number of partitions to create
     * @param method Partitioning method
     * @param lambda Lambda parameter for HDRF (balancing weight)
     * @param hdf High-degree factor threshold
     * @return Map of partition files created
     */
    std::map<int, std::string> partitionWithParams(const string& inputFilePath,
                                                    int graphID,
                                                    int partitionCount,
                                                    const string& method,
                                                    double lambda = 1.1,
                                                    double hdf = 100.0);

    /**
     * Get statistics about the last partitioning operation
     * 
     * @return Map containing partition statistics
     */
    std::map<string, string> getPartitionStats();

    /**
     * Validate FSM method name
     * 
     * @param method Method name to validate
     * @return true if valid, false otherwise
     */
    static bool isValidMethod(const string& method);

    /**
     * Get list of supported FSM methods
     * 
     * @return Vector of method names
     */
    static std::vector<string> getSupportedMethods();

 private:
    SQLiteDBInterface *sqlite;
    int lastGraphID;
    string lastMethod;
    std::map<string, string> lastStats;

    /**
     * Execute FSM partitioner with given parameters
     * 
     * @param args Command line arguments for FSM
     * @param outputDir Directory where partition files will be created
     * @return true if successful, false otherwise
     */
    bool executeFSM(const std::vector<string>& args, const string& outputDir);

    /**
     * Parse FSM output and extract statistics
     * 
     * @param fsmOutput Output from FSM execution
     */
    void parseStats(const string& fsmOutput);

    /**
     * Create partition file mapping for JasmineGraph
     * 
     * @param outputDir Directory containing FSM output files
     * @param graphID Graph identifier
     * @param partitionCount Number of partitions
     * @return Map of partition files
     */
    std::map<int, std::string> createPartitionFileMap(const string& outputDir,
                                                       int graphID,
                                                       int partitionCount);
};

#endif // JASMINEGRAPH_FSMPARTITIONER_H
