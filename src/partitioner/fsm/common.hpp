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
    bool fastmerge = false;
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
#define FLAGS_fastmerge FLAGS.fastmerge

// Create static logger for FSM framework
static Logger fsm_framework_logger;

// Helper class to support CHECK(condition) << "message" syntax
class FSMCheckStream {
    std::ostringstream oss;
    bool failed;
public:
    FSMCheckStream(bool condition_failed, const std::string& msg) : failed(condition_failed) {
        if (failed) {
            oss << msg;
        }
    }
    ~FSMCheckStream() {
        if (failed && oss.str().length() > 0) {
            fsm_framework_logger.error(oss.str());
        }
    }
    template<typename T>
    FSMCheckStream& operator<<(const T& val) {
        if (failed) {
            oss << val;
        }
        return *this;
    }
    FSMCheckStream& operator<<(std::ostream& (*manip)(std::ostream&)) {
        if (failed) {
            oss << manip;
        }
        return *this;
    }
};

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

// Replace glog LOG and CHECK macros with JasmineGraph logger
#define LOG(level) FSMLogStream(#level).stream()
#define DLOG(level) FSMLogStream(#level).stream()  // Debug log (same as LOG in our case)
#define CHECK(condition) FSMCheckStream(!(condition), std::string("CHECK failed: ") + #condition)
#define CHECK_LT(a, b) FSMCheckStream(!((a) < (b)), std::string("CHECK_LT failed: ") + #a + " < " + #b)
#define CHECK_LE(a, b) FSMCheckStream(!((a) <= (b)), std::string("CHECK_LE failed: ") + #a + " <= " + #b)
#define CHECK_GT(a, b) FSMCheckStream(!((a) > (b)), std::string("CHECK_GT failed: ") + #a + " > " + #b)
#define CHECK_GE(a, b) FSMCheckStream(!((a) >= (b)), std::string("CHECK_GE failed: ") + #a + " >= " + #b)
#define CHECK_EQ(a, b) FSMCheckStream(!((a) == (b)), std::string("CHECK_EQ failed: ") + #a + " == " + #b)
#define CHECK_NE(a, b) FSMCheckStream(!((a) != (b)), std::string("CHECK_NE failed: ") + #a + " != " + #b)

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