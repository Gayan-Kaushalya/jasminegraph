#ifndef COMMON_HPP
#define COMMON_HPP

#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <chrono>
#include <sys/stat.h>
#include <sstream>

// Use JasmineGraph's logger instead of glog
#include "../../util/logger/Logger.h"

// Replace gflags with simple global struct
// These are set programmatically by FSMPartitioner, not parsed from command line
struct FSMFlags {
    int32_t p = 0;
    int32_t k = 0;
    std::string filename;
    std::string filetype;
    std::string method;
    std::string write;
    double hdf = 0.0;
    double lambda = 0.0;
    bool write_low_degree_edgelist = false;
    bool extended_metrics = false;
    bool hybrid_NE = false;
};

// Global FLAGS instance
inline FSMFlags FLAGS;

// Macros for compatibility with original FSM code that uses DECLARE_*
#define DECLARE_int32(name)
#define DECLARE_string(name)
#define DECLARE_double(name)
#define DECLARE_bool(name)

// Map FLAGS_* to struct fields for compatibility
#define FLAGS_p FLAGS.p
#define FLAGS_k FLAGS.k
#define FLAGS_filename FLAGS.filename
#define FLAGS_filetype FLAGS.filetype
#define FLAGS_method FLAGS.method
#define FLAGS_write FLAGS.write
#define FLAGS_hdf FLAGS.hdf
#define FLAGS_lambda FLAGS.lambda
#define FLAGS_write_low_degree_edgelist FLAGS.write_low_degree_edgelist
#define FLAGS_extended_metrics FLAGS.extended_metrics
#define FLAGS_hybrid_NE FLAGS.hybrid_NE

// Create static logger for FSM framework
static Logger fsm_framework_logger;

// Replace glog LOG macros with JasmineGraph logger
#define LOG(level) FSMLogStream(#level).stream()
#define CHECK(condition) if(!(condition)) fsm_framework_logger.error(std::string("CHECK failed: ") + #condition), std::cerr
#define CHECK_LT(a, b) if(!((a) < (b))) { std::ostringstream oss; oss << "CHECK_LT failed: " << #a << " < " << #b << " (" << (a) << " < " << (b) << ")"; fsm_framework_logger.error(oss.str()); } static_cast<void>(0)
#define CHECK_LE(a, b) if(!((a) <= (b))) { std::ostringstream oss; oss << "CHECK_LE failed: " << #a << " <= " << #b << " (" << (a) << " <= " << (b) << ")"; fsm_framework_logger.error(oss.str()); } static_cast<void>(0)
#define CHECK_GT(a, b) if(!((a) > (b))) { std::ostringstream oss; oss << "CHECK_GT failed: " << #a << " > " << #b << " (" << (a) << " > " << (b) << ")"; fsm_framework_logger.error(oss.str()); } static_cast<void>(0)
#define CHECK_GE(a, b) if(!((a) >= (b))) { std::ostringstream oss; oss << "CHECK_GE failed: " << #a << " >= " << #b << " (" << (a) << " >= " << (b) << ")"; fsm_framework_logger.error(oss.str()); } static_cast<void>(0)
#define CHECK_EQ(a, b) if(!((a) == (b))) { std::ostringstream oss; oss << "CHECK_EQ failed: " << #a << " == " << #b << " (" << (a) << " == " << (b) << ")"; fsm_framework_logger.error(oss.str()); } static_cast<void>(0)
#define CHECK_NE(a, b) if(!((a) != (b))) { std::ostringstream oss; oss << "CHECK_NE failed: " << #a << " != " << #b << " (" << (a) << " != " << (b) << ")"; fsm_framework_logger.error(oss.str()); } static_cast<void>(0)

// Helper class to support LOG(level) << "message" syntax
class FSMLogStream {
    std::string level;
    std::ostringstream oss;
public:
    FSMLogStream(const std::string& lvl) : level(lvl) {}
    ~FSMLogStream() {
        if (level == "INFO") {
            fsm_framework_logger.info(oss.str());
        } else if (level == "WARNING") {
            fsm_framework_logger.warn(oss.str());
        } else if (level == "ERROR" || level == "FATAL") {
            fsm_framework_logger.error(oss.str());
        } else {
            fsm_framework_logger.info(oss.str());
        }
    }
    std::ostream& stream() { return oss; }
};

using vid_t = uint32_t;
using eid_t = uint64_t;
using bid_t = uint8_t;
const vid_t kInvalidVid = std::numeric_limits<vid_t>::max();
const bid_t kInvalidBid = std::numeric_limits<bid_t>::max();
const vid_t offset = (vid_t)1 << 31;

struct edge_t {
    vid_t first, second;
    edge_t() : first(0), second(0) {}
    edge_t(vid_t first, vid_t second) : first(first), second(second) {}
    // const bool valid() { return first != INVALID_VID; }
    // void remove() { first = INVALID_VID; }
    bool valid() const { return first < offset; }
    void remove() { first += offset; }
    void recover() {
        if (first >= offset) {
            first -= offset;
        }
    }
    bool operator == (const edge_t & rhs) const {
        return first == rhs.first && second == rhs.second;
    }
};

#endif