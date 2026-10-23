# Browse the owner's sources; production compilation reuses the component CMake definition.
file(GLOB_RECURSE sources LIST_DIRECTORIES false
    "${ASTRA_ROOT}/${directory}/*.cpp" "${ASTRA_ROOT}/${directory}/*.hpp"
    "${ASTRA_ROOT}/${directory}/*.cc" "${ASTRA_ROOT}/${directory}/*.c"
    "${ASTRA_ROOT}/${directory}/*.h" "${ASTRA_ROOT}/${directory}/*.cmake"
    "${ASTRA_ROOT}/${directory}/CMakeLists.txt" "${ASTRA_ROOT}/${directory}/*.md")
list(FILTER sources EXCLUDE REGEX "/(build|CMakeFiles)/")
source_group(TREE "${ASTRA_ROOT}/${directory}" FILES ${sources})
add_custom_target(${component}
    COMMAND "${ASTRA_PYTHON}" -B "${ASTRA_ROOT}/tools/solution.py" --build "${component}" --config "$<CONFIG>"
    SOURCES ${sources}
    WORKING_DIRECTORY "${ASTRA_ROOT}" VERBATIM)
# Utility projects are excluded from Build Solution; Build Project invokes the explicit action.
set_target_properties(${component} PROPERTIES EXCLUDE_FROM_ALL TRUE EXCLUDE_FROM_DEFAULT_BUILD TRUE)
set_property(TARGET ${component} PROPERTY VS_GLOBAL_IntDir "${CMAKE_CURRENT_BINARY_DIR}/intermediate/$(Configuration)/")
if(NOT component STREQUAL "Comet" OR ASTRA_BROWSE_ONLY)
    set_property(TARGET ${component} PROPERTY PROJECT_LABEL "${component} (browse only)")
endif()
