# Multilevel Spectral Partitioning Integration

## Overview

This document describes the integration of multilevel spectral graph partitioning into JasmineGraph's ADSP (Add Graph Spectral) workflow. The implementation combines three powerful techniques:

1. **Multilevel Coarsening**: Progressively reduces graph size using heavy-edge matching
2. **Spectral Clustering**: Uses eigengap heuristic for automatic partition count selection
3. **Hierarchical Refinement**: Improves partition quality through uncoarsening

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend Command Layer                    │
│  ┌──────────┐  ┌──────────┐  ┌─────────────────────────┐   │
│  │   ADGR   │  │   ADSP   │  │       ADMLSP (NEW)      │   │
│  │  (METIS) │  │(Spectral)│  │ (Multilevel Spectral)   │   │
│  └──────────┘  └──────────┘  └─────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  Partitioner Layer                           │
│  ┌─────────────────────┐  ┌──────────────────────────────┐ │
│  │ SpectralPartitioner │  │ MultilevelSpectralPartitioner│ │
│  │  - Eigengap         │  │  - Coarsening                │ │
│  │  - Power Iteration  │  │  - Heavy Edge Matching       │ │
│  │  - K-means          │  │  - Uses SpectralPartitioner  │ │
│  └─────────────────────┘  │  - Refinement                │ │
│                            └──────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Key Classes

#### MultilevelSpectralPartitioner
Main class implementing the multilevel algorithm:
- **Location**: `src/partitioner/local/MultilevelSpectralPartitioner.{h,cpp}`
- **Dependencies**: SpectralPartitioner, SQLiteDBInterface, Utils, Logger
- **Key Methods**:
  - `loadGraph()`: Load graph from edge list
  - `partition()`: Execute full multilevel algorithm
  - `buildHierarchy()`: Coarsening phase
  - `initialPartition()`: Use SpectralPartitioner on coarsest graph
  - `projectPartitions()`: Uncoarsening phase
  - `refinePartitions()`: Local improvement via boundary moves
  - `savePartitions()`: Write partition files

#### MultilevelConfig
Configuration structure for tuning the algorithm:
```cpp
struct MultilevelConfig {
    int coarseLimit = 20000;          // Stop coarsening at this size
    int maxK = 16;                     // Max partitions for eigengap
    double balanceEpsilon = 1.03;      // 3% imbalance tolerance
    int maxCoarsenLevels = 10;         // Max coarsening iterations
    bool useParallelMatching = true;   // Enable OpenMP
    bool useBalancedClustering = true; // Balanced k-means
};
```

## Algorithm Workflow

### Phase 1: Coarsening (Bottom-Up)
```
Original Graph (n vertices)
    │
    │ Heavy Edge Matching
    ▼
Level 0 (n/2 vertices)
    │
    │ Heavy Edge Matching
    ▼
Level 1 (n/4 vertices)
    │
    ⋮
    │
    ▼
Coarsest Level (~20K vertices)
```

**Heavy Edge Matching**:
- Each vertex matches with its "heaviest" neighbor
- Matched vertices collapse into super-vertices
- Reduces graph size by ~50% per level
- Optional OpenMP parallelization for large graphs

### Phase 2: Initial Partitioning
On the coarsest graph:
1. Construct normalized Laplacian: L = I - D^(-1/2) A D^(-1/2)
2. Compute eigenvalues using power iteration
3. Find eigengap: max(λ[i+1] - λ[i]) → determines k
4. Compute k eigenvectors
5. Run k-means clustering on eigenvector matrix

### Phase 3: Uncoarsening (Top-Down)
```
Coarsest Level (partitioned)
    │
    │ Project + Refine
    ▼
Level 1 (refined)
    │
    │ Project + Refine
    ▼
Level 0 (refined)
    │
    ⋮
    │
    ▼
Original Graph (final partitions)
```

**Projection**: Map each fine vertex to its coarse representative's partition

**Refinement**: Kernighan-Lin style boundary moves:
- Move vertices with more external than internal edges
- Maintain balance constraint (balanceEpsilon)
- Improve edge cut quality

## Usage

### Command Line (via Frontend)

#### Using ADMLSP (Multilevel Spectral)
```bash
# Connect to JasmineGraph frontend
echo "admlsp" | nc localhost 7777

# Response: "send"

# Send: <graph_name>|<path_to_edge_list>
echo "mygraph|/path/to/edges.txt" | nc localhost 7777

# Automatic k selection via eigengap
# Returns: "done" when complete
```

#### Using ADSP (Basic Spectral)
```bash
echo "adsp" | nc localhost 7777
echo "mygraph|/path/to/edges.txt" | nc localhost 7777
```

### Programmatic Usage

```cpp
#include "partitioner/local/MultilevelSpectralPartitioner.h"

// Configure
MultilevelConfig config;
config.coarseLimit = 20000;
config.maxK = 16;
config.balanceEpsilon = 1.03;

// Create partitioner
MultilevelSpectralPartitioner partitioner(sqlite, config);

// Load graph
partitioner.loadGraph("graph.txt", graphID);

// Partition (0 = automatic k selection)
vector<int> labels = partitioner.partition(0);

// Save to files
map<int, string> files = partitioner.savePartitions(labels);

// Get statistics
int k = *max_element(labels.begin(), labels.end()) + 1;
int levels = partitioner.getCoarsenLevels();
vector<double> evals = partitioner.getEigenvalues();
```

## Performance Characteristics

### Time Complexity
- **Coarsening**: O(|E| × L) where L = coarsening levels (~log n)
- **Spectral**: O(k × m × |V_c| + k² × |V_c|) on coarsest graph
  - m = power iterations (~100-200)
  - |V_c| = coarsest graph size (~20K)
- **Uncoarsening**: O(|E| × L)
- **Total**: O(|E| × log n + k × m × 20K)

Much faster than basic spectral: O(k × m × |V|) where |V| could be millions

### Space Complexity
- O(|V| + |E|): Original graph in CSR format
- O(L × |V|/2^L): Hierarchy storage (dominated by finest levels)
- O(k × |V_c|): Eigenvector storage on coarsest graph
- **Total**: O(|V| + |E|) effectively

### Scalability
- **Small graphs** (<100K vertices): Use ADSP (basic spectral)
- **Medium graphs** (100K-10M vertices): Use ADMLSP (multilevel)
- **Large graphs** (>10M vertices): ADMLSP with lower coarseLimit

## Comparison with ADSP

| Aspect | ADSP (Basic Spectral) | ADMLSP (Multilevel) |
|--------|----------------------|---------------------|
| **Graph Size** | Up to ~100K vertices | Millions of vertices |
| **Time** | O(k × m × n) | O(k × m × 20K) |
| **Quality** | Good | Better (refinement) |
| **Balance** | Standard k-means | Balanced k-means |
| **k Selection** | Eigengap (full graph) | Eigengap (coarse graph) |
| **Parallelism** | Power iteration only | + Matching + Refinement |

## Configuration Guidelines

### coarseLimit
- **Default**: 20,000 vertices
- **Smaller** (5K-10K): Faster initial partition, may need more refinement
- **Larger** (50K-100K): Better initial quality, slower spectral phase

### maxK
- **Default**: 16 partitions
- Set based on cluster size or application needs
- Eigengap may select k < maxK

### balanceEpsilon
- **Default**: 1.03 (3% imbalance)
- **Stricter** (1.01): More balanced, possibly worse cut
- **Relaxed** (1.10): Better cut, more imbalance

### maxCoarsenLevels
- **Default**: 10 levels
- Usually stops due to coarseLimit before hitting this
- Safety limit to prevent over-coarsening

## Integration with JasmineGraph

### Protocol
- **Command**: `ADMLSP` (defined in JasmineGraphFrontEndProtocol)
- **Format**: `<graph_name>|<path>`
- **Response**: `DONE` on success, `ERROR: ...` on failure

### Database Updates
Automatically updates `graph` table:
```sql
UPDATE graph SET 
    vertexcount = '<n>',
    centralpartitioncount = '<k>',
    edgecount = '<m>'
WHERE idgraph = '<graphID>'
```

### File Outputs
Creates files in `~/.jasminegraph/tmp/<graphID>/`:
- `<graphID>_partition_0.txt` through `<graphID>_partition_<k-1>.txt`
- `<graphID>_centralstore_<i>` (empty, required by system)
- `<graphID>_centralstore_dp_<i>` (empty, required by system)

### Logging
Detailed logging via `multilevel_logger`:
- Coarsening progress: reduction ratios per level
- Initial partitioning: eigenvalues, selected k
- Refinement: iterations, metrics
- Final statistics: edge cut, imbalance
- Timing: coarsening, partitioning, uncoarsening, total

## Future Enhancements

### Distributed Computing (from original code snippet)
The algorithm can be extended with MPI+OpenMP:
- Distribute graph across processes (vertex partitioning)
- Use PETSc for distributed sparse matrices
- Use SLEPc for distributed eigenvalue computation
- Parallel refinement across boundaries

### Advanced Features
1. **Edge Weights**: Support weighted graphs in matching
2. **Node Weights**: Non-uniform vertex weights for balancing
3. **Multi-constraint**: Balance multiple attributes
4. **K-way Refinement**: Global refinement instead of boundary-only
5. **Rebalancing**: Dynamic partition adjustment

### Performance Optimizations
1. **SIMD**: Vectorize matrix-vector products
2. **Cache**: Improve CSR memory layout
3. **GPU**: Port eigenvalue computation to GPU
4. **Compression**: Reduce memory for hierarchy storage

## Troubleshooting

### Common Issues

**Issue**: Coarsening stalls (reduction < 5%)
- **Cause**: Graph has many isolated components or is already coarse
- **Solution**: Lower coarseLimit or use basic ADSP

**Issue**: Eigengap selects k=2 for complex graphs
- **Cause**: Weak community structure
- **Solution**: Manually specify k or use different partitioner

**Issue**: High imbalance in final partitions
- **Cause**: balanceEpsilon too relaxed or graph structure
- **Solution**: Decrease balanceEpsilon, adjust coarseLimit

**Issue**: Slow partitioning on small graphs
- **Cause**: Multilevel overhead not worth it
- **Solution**: Use basic ADSP for graphs < 100K vertices

## References

1. **Multilevel**: Karypis & Kumar, "A Fast and High Quality Multilevel Scheme for Partitioning Irregular Graphs", SIAM 1998
2. **Spectral**: Von Luxburg, "A Tutorial on Spectral Clustering", Statistics and Computing 2007
3. **Eigengap**: Zelnik-Manor & Perona, "Self-Tuning Spectral Clustering", NIPS 2004
4. **Balanced K-means**: Malinen & Fränti, "Balanced K-Means for Clustering", JMLR 2014

## Contact

For questions or contributions:
- JasmineGraph Team: https://github.com/miyurud/jasminegraph
- Documentation: https://github.com/miyurud/jasminegraph/wiki
