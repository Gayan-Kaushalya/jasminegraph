/**
 * Integration Guide: Adaptive Fennel Partitioning in JasmineGraph Frontend
 * 
 * This guide shows how to modify the frontend to support adaptive partitioning
 * for streaming graph ingestion from Kafka.
 */

/*
 * ============================================================================
 * STEP 1: Modify addStreamKafkaCommand in JasmineGraphFrontEnd.cpp
 * ============================================================================
 * 
 * Location: src/frontend/JasmineGraphFrontEnd.cpp
 * Function: addStreamKafkaCommand()
 * 
 * Add user prompts to configure adaptive partitioning
 */

// After getting partitionAlgo and numberOfPartitions, add:
void addStreamKafkaCommand_ADAPTIVE_EXAMPLE(int connFd, SQLiteDBInterface *sqlite) {
    // ... existing code to get partitionAlgo, numberOfPartitions, etc ...
    
    // NEW: Check if user wants adaptive partitioning (only for Fennel)
    bool useAdaptivePartitioning = false;
    int minPartitions = numberOfPartitions;
    int maxPartitions = numberOfPartitions;
    double edgeCutThreshold = 0.3;
    double imbalanceThreshold = 1.5;
    long checkInterval = 1000;
    
    if (partitionAlgo == "2") {  // Fennel algorithm
        std::string adaptiveMessage = "Enable adaptive partitioning? (y/n): ";
        int resultWr = write(connFd, adaptiveMessage.c_str(), adaptiveMessage.length());
        write(connFd, Conts::CARRIAGE_RETURN_NEW_LINE.c_str(), Conts::CARRIAGE_RETURN_NEW_LINE.size());
        
        char adaptiveResponse[FRONTEND_DATA_LENGTH + 1];
        bzero(adaptiveResponse, FRONTEND_DATA_LENGTH + 1);
        read(connFd, adaptiveResponse, FRONTEND_DATA_LENGTH);
        std::string adaptiveResponseStr(adaptiveResponse);
        adaptiveResponseStr = Utils::trim_copy(adaptiveResponseStr);
        
        if (adaptiveResponseStr == "y" || adaptiveResponseStr == "yes") {
            useAdaptivePartitioning = true;
            
            // Get minimum partitions
            std::string minPartMsg = "Minimum partitions to start with: ";
            write(connFd, minPartMsg.c_str(), minPartMsg.length());
            write(connFd, Conts::CARRIAGE_RETURN_NEW_LINE.c_str(), Conts::CARRIAGE_RETURN_NEW_LINE.size());
            
            char minPartBuf[FRONTEND_DATA_LENGTH + 1];
            bzero(minPartBuf, FRONTEND_DATA_LENGTH + 1);
            read(connFd, minPartBuf, FRONTEND_DATA_LENGTH);
            minPartitions = std::stoi(Utils::trim_copy(std::string(minPartBuf)));
            
            // Get maximum partitions
            std::string maxPartMsg = "Maximum partitions allowed: ";
            write(connFd, maxPartMsg.c_str(), maxPartMsg.length());
            write(connFd, Conts::CARRIAGE_RETURN_NEW_LINE.c_str(), Conts::CARRIAGE_RETURN_NEW_LINE.size());
            
            char maxPartBuf[FRONTEND_DATA_LENGTH + 1];
            bzero(maxPartBuf, FRONTEND_DATA_LENGTH + 1);
            read(connFd, maxPartBuf, FRONTEND_DATA_LENGTH);
            maxPartitions = std::stoi(Utils::trim_copy(std::string(maxPartBuf)));
            
            // Optional: Ask for threshold configuration
            std::string advancedMsg = "Configure advanced thresholds? (y/n, default n): ";
            write(connFd, advancedMsg.c_str(), advancedMsg.length());
            write(connFd, Conts::CARRIAGE_RETURN_NEW_LINE.c_str(), Conts::CARRIAGE_RETURN_NEW_LINE.size());
            
            char advancedBuf[FRONTEND_DATA_LENGTH + 1];
            bzero(advancedBuf, FRONTEND_DATA_LENGTH + 1);
            read(connFd, advancedBuf, FRONTEND_DATA_LENGTH);
            std::string advancedStr = Utils::trim_copy(std::string(advancedBuf));
            
            if (advancedStr == "y" || advancedStr == "yes") {
                // Get edge cut threshold
                std::string ectMsg = "Edge cut threshold (0.0-1.0, default 0.3): ";
                write(connFd, ectMsg.c_str(), ectMsg.length());
                write(connFd, Conts::CARRIAGE_RETURN_NEW_LINE.c_str(), Conts::CARRIAGE_RETURN_NEW_LINE.size());
                
                char ectBuf[FRONTEND_DATA_LENGTH + 1];
                bzero(ectBuf, FRONTEND_DATA_LENGTH + 1);
                read(connFd, ectBuf, FRONTEND_DATA_LENGTH);
                std::string ectStr = Utils::trim_copy(std::string(ectBuf));
                if (!ectStr.empty()) {
                    edgeCutThreshold = std::stod(ectStr);
                }
                
                // Get imbalance threshold
                std::string ibtMsg = "Imbalance threshold (>1.0, default 1.5): ";
                write(connFd, ibtMsg.c_str(), ibtMsg.length());
                write(connFd, Conts::CARRIAGE_RETURN_NEW_LINE.c_str(), Conts::CARRIAGE_RETURN_NEW_LINE.size());
                
                char ibtBuf[FRONTEND_DATA_LENGTH + 1];
                bzero(ibtBuf, FRONTEND_DATA_LENGTH + 1);
                read(connFd, ibtBuf, FRONTEND_DATA_LENGTH);
                std::string ibtStr = Utils::trim_copy(std::string(ibtBuf));
                if (!ibtStr.empty()) {
                    imbalanceThreshold = std::stod(ibtStr);
                }
                
                // Get check interval
                std::string ciMsg = "Check interval (edges, default 1000): ";
                write(connFd, ciMsg.c_str(), ciMsg.length());
                write(connFd, Conts::CARRIAGE_RETURN_NEW_LINE.c_str(), Conts::CARRIAGE_RETURN_NEW_LINE.size());
                
                char ciBuf[FRONTEND_DATA_LENGTH + 1];
                bzero(ciBuf, FRONTEND_DATA_LENGTH + 1);
                read(connFd, ciBuf, FRONTEND_DATA_LENGTH);
                std::string ciStr = Utils::trim_copy(std::string(ciBuf));
                if (!ciStr.empty()) {
                    checkInterval = std::stol(ciStr);
                }
            }
            
            std::string configMsg = "Adaptive config: min=" + std::to_string(minPartitions) + 
                                   ", max=" + std::to_string(maxPartitions) + 
                                   ", edgeCutThreshold=" + std::to_string(edgeCutThreshold) + 
                                   ", imbalanceThreshold=" + std::to_string(imbalanceThreshold);
            write(connFd, configMsg.c_str(), configMsg.length());
            write(connFd, Conts::CARRIAGE_RETURN_NEW_LINE.c_str(), Conts::CARRIAGE_RETURN_NEW_LINE.size());
        }
    }
    
    // ... existing code to get kafka configs, topic, etc ...
    
    // MODIFY: Create StreamHandler with adaptive mode if enabled
    StreamHandler *stream_handler;
    
    if (useAdaptivePartitioning) {
        stream_handler = new StreamHandler(
            kstream, 
            minPartitions,
            maxPartitions,
            workerClients, 
            sqlite, 
            stoi(graphId),
            direction == Conts::DIRECTED, 
            spt::getPartitioner(partitionAlgo),
            edgeCutThreshold,
            imbalanceThreshold,
            checkInterval
        );
    } else {
        stream_handler = new StreamHandler(
            kstream, 
            numberOfPartitions,
            workerClients, 
            sqlite, 
            stoi(graphId),
            direction == Conts::DIRECTED, 
            spt::getPartitioner(partitionAlgo)
        );
    }
    
    // ... rest of the existing code ...
}

/*
 * ============================================================================
 * STEP 2: Update Graph Database Schema (Optional)
 * ============================================================================
 * 
 * If you want to track adaptive partitioning configuration in the database,
 * modify ddl/metadb.sql to add columns to the graph table:
 */

/*
ALTER TABLE graph ADD COLUMN adaptive_partitioning BOOLEAN DEFAULT 0;
ALTER TABLE graph ADD COLUMN min_partitions INTEGER;
ALTER TABLE graph ADD COLUMN max_partitions INTEGER;
ALTER TABLE graph ADD COLUMN edge_cut_threshold REAL;
ALTER TABLE graph ADD COLUMN imbalance_threshold REAL;
ALTER TABLE graph ADD COLUMN final_partition_count INTEGER;
*/

/*
 * Then update the SQL insert statement in addStreamKafkaCommand:
 */

// Example SQL update
void updateGraphTableForAdaptive() {
    /*
    if (useAdaptivePartitioning) {
        sqlStatement =
            "INSERT INTO graph (idgraph,id_algorithm,name,upload_path, upload_start_time, upload_end_time,"
            "graph_status_idgraph_status, vertexcount, centralpartitioncount, edgecount, is_directed, "
            "adaptive_partitioning, min_partitions, max_partitions, edge_cut_threshold, imbalance_threshold) VALUES(" +
            graphId + "," + partitionAlgo + ",\"" + topic_name_s + "\", \"" + path + "\", \"" + uploadStartTime +
            "\", \"\",\"" + to_string(Conts::GRAPH_STATUS::STREAMING) + "\", \"\"," + to_string(minPartitions) +
            ", \"\",\"" + direction + "\", 1, " + to_string(minPartitions) + ", " + to_string(maxPartitions) +
            ", " + to_string(edgeCutThreshold) + ", " + to_string(imbalanceThreshold) + ")";
    } else {
        // ... existing non-adaptive SQL ...
    }
    */
}

/*
 * ============================================================================
 * STEP 3: Simple Configuration via Properties File
 * ============================================================================
 * 
 * For easier deployment, add default adaptive settings to:
 * conf/jasminegraph-server.properties
 */

/*
# Adaptive Fennel Partitioning Configuration
org.jasminegraph.adaptive.enabled=false
org.jasminegraph.adaptive.min_partitions=2
org.jasminegraph.adaptive.max_partitions=16
org.jasminegraph.adaptive.edge_cut_threshold=0.3
org.jasminegraph.adaptive.imbalance_threshold=1.5
org.jasminegraph.adaptive.check_interval=1000
*/

/*
 * Then read these properties in the code:
 */

void readAdaptivePropertiesExample() {
    /*
    bool adaptiveEnabled = Utils::getJasmineGraphProperty("org.jasminegraph.adaptive.enabled") == "true";
    int minPartitions = std::stoi(Utils::getJasmineGraphProperty("org.jasminegraph.adaptive.min_partitions"));
    int maxPartitions = std::stoi(Utils::getJasmineGraphProperty("org.jasminegraph.adaptive.max_partitions"));
    double edgeCutThreshold = std::stod(Utils::getJasmineGraphProperty("org.jasminegraph.adaptive.edge_cut_threshold"));
    double imbalanceThreshold = std::stod(Utils::getJasmineGraphProperty("org.jasminegraph.adaptive.imbalance_threshold"));
    long checkInterval = std::stol(Utils::getJasmineGraphProperty("org.jasminegraph.adaptive.check_interval"));
    */
}

/*
 * ============================================================================
 * STEP 4: CLI Example Usage
 * ============================================================================
 * 
 * When users run the stream command, the interaction would look like:
 */

/*
jasminegraph> addstream
Select upload method:
    option 1: Kafka
    option 2: HDFS
1
Select the partitioning algorithm:
    option 1: hash partitioning
    option 2: Fennel partitioning
    option 3: LDG partitioning
2
Partitions: 4
Enable adaptive partitioning? (y/n): y
Minimum partitions to start with: 2
Maximum partitions allowed: 8
Configure advanced thresholds? (y/n, default n): n
Adaptive config: min=2, max=8, edgeCutThreshold=0.300000, imbalanceThreshold=1.500000
... (rest of kafka configuration)
*/

/*
 * ============================================================================
 * STEP 5: Monitoring and Logging
 * ============================================================================
 * 
 * To monitor adaptive partitioning in action, the logs will show:
 */

/*
[INFO] StreamHandler initialized with adaptive partitioning: min=2, max=8
[INFO] Quality check: EdgeCutRatio=0.42, Imbalance=1.15, Partitions=2
[INFO] Added new partition #2. Total partitions: 3
[INFO] Quality check: EdgeCutRatio=0.38, Imbalance=1.22, Partitions=3
[INFO] Added new partition #3. Total partitions: 4
[INFO] Quality check: EdgeCutRatio=0.31, Imbalance=1.18, Partitions=4
[INFO] Quality check: EdgeCutRatio=0.28, Imbalance=1.12, Partitions=4
... (no more growth, quality is good)
*/

/*
 * ============================================================================
 * QUICK START: Minimal Changes for Testing
 * ============================================================================
 * 
 * For quick testing without modifying frontend, you can directly use:
 */

void quickTestExample() {
    /*
    // In your test code or modified frontend:
    SQLiteDBInterface* sqlite = new SQLiteDBInterface();
    sqlite->init();
    
    // Create adaptive partitioner
    Partitioner adaptivePartitioner(
        2,      // Start with 2 partitions
        8,      // Max 8 partitions
        graphID,
        spt::Algorithms::FENNEL,
        sqlite,
        false,  // undirected
        0.3,    // edge cut threshold
        1.5,    // imbalance threshold
        1000    // check every 1000 edges
    );
    
    // Use it
    for (auto& edge : edgeStream) {
        auto partitionedEdge = adaptivePartitioner.addEdge(edge);
        // ... process partitioned edge ...
    }
    
    // Check results
    std::cout << "Final partitions: " << adaptivePartitioner.getCurrentPartitionCount() << std::endl;
    std::cout << "Edge cut ratio: " << adaptivePartitioner.calculateEdgeCutRatio() << std::endl;
    std::cout << "Imbalance: " << adaptivePartitioner.calculateImbalance() << std::endl;
    */
}
