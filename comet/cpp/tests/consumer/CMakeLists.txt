# Verify installed SDK consumption without source-tree or private-header dependencies.
cmake_minimum_required(VERSION 3.28)
project(CometConsumer LANGUAGES CXX)

# Use the same consumer for source-tree and installed-package checks, without private headers or Star linkage.
if(COMET_SOURCE)
    add_subdirectory("${COMET_SOURCE}" comet)
else()
    find_package(Comet CONFIG REQUIRED)
endif()
add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE comet::comet)
