# Build the legacy adapter separately from Comet for comparable application workloads.
cmake_minimum_required(VERSION 3.28)
project(astra_redis_baseline LANGUAGES C CXX)

# Keep the two TLS implementations out of the same process; fail explicitly when the offline cache is absent.
set(VERDANDI_BUILD_TESTS OFF CACHE BOOL "Baseline only" FORCE)
set(VERDANDI_OFFLINE_DEPENDENCIES ON CACHE BOOL "No network access" FORCE)
set(VCPKG_MANIFEST_INSTALL OFF CACHE BOOL "No implicit installation" FORCE)
set(ASTRA_LEGACY_SDK "" CACHE PATH "Explicit path to the legacy Redis SDK root")
if(NOT EXISTS "${ASTRA_LEGACY_SDK}/cpp/CMakeLists.txt")
    message(FATAL_ERROR "Set ASTRA_LEGACY_SDK to an existing legacy SDK; no download is performed")
endif()
add_subdirectory("${ASTRA_LEGACY_SDK}/cpp" legacy)
add_executable(baseline_redis redis.cpp workload.cpp ../measure.cpp)
target_link_libraries(baseline_redis PRIVATE verdandi::verdandi)
target_compile_features(baseline_redis PRIVATE cxx_std_23)
verdandi_enable_warnings(baseline_redis)
