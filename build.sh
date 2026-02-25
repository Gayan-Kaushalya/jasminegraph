#!/bin/bash

# Clean stale CMake build artifacts to avoid conflicts with
# pre-existing build files from the base Docker image
rm -rf CMakeCache.txt CMakeFiles/

if [ "$1" = "--debug" ]; then
    cmake -DCMAKE_ENABLE_DEBUG=1 .
else
    cmake .
fi
cmake --build . --target JasmineGraph -- -j 4
