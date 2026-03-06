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

#include "SheepTriangles.h"
#include "../../../util/logger/Logger.h"
#include "../../../util/telemetry/OpenTelemetryUtil.h"
#include <chrono>
#include <algorithm>
#include <set>
#include <unordered_map>
#include <sstream>

Logger sheep_triangle_logger;

long SheepTriangles::run(JasmineGraphHashMapLocalStore &graphDB,
                         JasmineGraphHashMapCentralStore &centralStore,
                         JasmineGraphHashMapDuplicateCentralStore &duplicateCentralStore,
                         std::string graphId,
                         std::string partitionId) {
    OTEL_TRACE_FUNCTION();
    
    std::string workerInfo = "worker_" + graphId + "_partition_" + partitionId;
    sheep_triangle_logger.info("###SHEEP-TRIANGLE### " + workerInfo + " Starting optimized sheep triangle counting");
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Extract data from stores
    std::map<long, std::unordered_set<long>> localMap;
    std::map<long, std::unordered_set<long>> centralMap;
    std::map<long, std::unordered_set<long>> duplicateMap;
    
    {
        ScopedTracer data_extract("sheep_extract_data");
        localMap = graphDB.getUnderlyingHashMap();
        centralMap = centralStore.getUnderlyingHashMap();
        duplicateMap = duplicateCentralStore.getUnderlyingHashMap();
    }
    
    // Merge stores efficiently
    {
        ScopedTracer merge_phase("sheep_merge_stores");
        mergeStores(localMap, centralMap, duplicateMap);
    }
    
    auto mergeEnd = std::chrono::high_resolution_clock::now();
    auto mergeDuration = std::chrono::duration_cast<std::chrono::milliseconds>(mergeEnd - startTime).count();
    sheep_triangle_logger.info("Merge time: " + std::to_string(mergeDuration) + " ms");
    
    // Count triangles with optimized algorithm
    SheepTriangleResult result;
    {
        ScopedTracer count_phase("sheep_count_triangles");
        result = countTriangles(localMap, false);
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    sheep_triangle_logger.info("###SHEEP-TRIANGLE### " + workerInfo + " Complete. Count: " + 
                              std::to_string(result.count) + " Time: " + std::to_string(totalDuration) + " ms");
    
    return result.count;
}

void SheepTriangles::mergeStores(
    std::map<long, std::unordered_set<long>> &localMap,
    std::map<long, std::unordered_set<long>> &centralMap,
    std::map<long, std::unordered_set<long>> &duplicateMap) {
    
    // Merge duplicate central into central (avoiding duplicates)
    for (const auto &entry : duplicateMap) {
        long vertex = entry.first;
        const auto &edges = entry.second;
        centralMap[vertex].insert(edges.begin(), edges.end());
    }
    
    // Merge central into local
    for (const auto &entry : centralMap) {
        long vertex = entry.first;
        const auto &edges = entry.second;
        localMap[vertex].insert(edges.begin(), edges.end());
    }
}

SheepTriangleResult SheepTriangles::countTriangles(
    std::map<long, std::unordered_set<long>> &edgeMap,
    bool returnTriangles) {

    SheepTriangleResult result;
    result.count = 0;

    std::basic_ostringstream<char> triangleStream;

    // Build degree distribution from the merged edge map — equivalent to trian's distributionMap.
    std::map<long, long> distributionMap;
    for (const auto &entry : edgeMap) {
        distributionMap[entry.first] = static_cast<long>(entry.second.size());
    }

    // --- Exact same steps as Triangles::countTriangles ---

    std::map<long, std::set<long>> degreeMap;
    for (auto it = distributionMap.begin(); it != distributionMap.end(); ++it) {
        long degree = it->second;
        if (degree == 1) continue;
        long startVertexId = it->first;
        degreeMap[degree].insert(startVertexId);
    }

    long triangleCount = 0;
    std::unordered_map<long, std::unordered_map<long, std::unordered_set<long>>> triangleTree;

    for (auto iterator = degreeMap.begin(); iterator != degreeMap.end(); ++iterator) {
        auto &vertices = iterator->second;
        for (auto verticesIterator = vertices.begin(); verticesIterator != vertices.end(); ++verticesIterator) {
            long temp = *verticesIterator;
            auto &unorderedUSet = edgeMap[temp];
            for (auto uSetIterator = unorderedUSet.begin(); uSetIterator != unorderedUSet.end(); ++uSetIterator) {
                long u = *uSetIterator;
                if (temp == u) continue;
                auto &unorderedNuSet = edgeMap[u];
                for (auto nuSetIterator = unorderedNuSet.begin(); nuSetIterator != unorderedNuSet.end();
                     ++nuSetIterator) {
                    long nu = *nuSetIterator;
                    if (temp == nu) continue;
                    if (u == nu) continue;
                    auto &edgeMapNu = edgeMap[nu];
                    if ((unorderedUSet.find(nu) != unorderedUSet.end()) ||
                        (edgeMapNu.find(temp) != edgeMapNu.end())) {
                        long varOne = temp;
                        long varTwo = u;
                        long varThree = nu;
                        if (varOne > varTwo) {
                            varOne ^= varTwo;
                            varTwo ^= varOne;
                            varOne ^= varTwo;
                        }
                        if (varOne > varThree) {
                            varOne ^= varThree;
                            varThree ^= varOne;
                            varOne ^= varThree;
                        }
                        if (varTwo > varThree) {
                            varTwo ^= varThree;
                            varThree ^= varTwo;
                            varTwo ^= varThree;
                        }
                        auto &itemRes = triangleTree[varOne];
                        auto itemResIterator = itemRes.find(varTwo);
                        if (itemResIterator != itemRes.end()) {
                            auto &set2 = itemRes[varTwo];
                            auto set2Iter = set2.find(varThree);
                            if (set2Iter == set2.end()) {
                                set2.insert(varThree);
                                triangleCount++;
                                if (returnTriangles) {
                                    triangleStream << varOne << "," << varTwo << "," << varThree << ":";
                                }
                            }
                        } else {
                            triangleTree[varOne][varTwo].insert(varThree);
                            triangleCount++;
                            if (returnTriangles) {
                                triangleStream << varOne << "," << varTwo << "," << varThree << ":";
                            }
                        }
                    }
                }
            }
        }
    }

    triangleTree.clear();

    // --- End of trian steps ---

    result.count = triangleCount;
    if (returnTriangles) {
        string triangles = triangleStream.str();
        if (triangles.empty()) {
            result.triangles = "NILL";
        } else {
            triangles.erase(triangles.size() - 1);
            result.triangles = std::move(triangles);
        }
    }

    return result;
}
