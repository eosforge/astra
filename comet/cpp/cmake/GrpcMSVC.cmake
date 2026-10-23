# Adapt pinned gRPC 1.84 for MSVC through CMAKE_PROJECT_grpc_INCLUDE without modifying dependency source.
# Disable only the optional fused implementation; normal authentication, compression, and size filters retain upstream registration.
if(MSVC AND PROJECT_NAME STREQUAL "grpc")
    if(NOT EXISTS "${PROJECT_SOURCE_DIR}/src/core/filter/fused_filters.cc")
        message(FATAL_ERROR "Comet MSVC compatibility requires the pinned gRPC filter layout")
    endif()
    # grpc and grpc_unsecure share this source. Keep the definition local rather than propagating it to the SDK or other dependencies.
    set_property(SOURCE "${PROJECT_SOURCE_DIR}/src/core/filter/fused_filters.cc" APPEND PROPERTY COMPILE_DEFINITIONS GRPC_NO_FILTER_FUSION=1)
endif()
