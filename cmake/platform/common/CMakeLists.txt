# Shared time logic and native primitives remain in Common's own build directory.
add_library(astra_platform STATIC
    "${ASTRA_ROOT}/common/src/clock.cpp"
    "${ASTRA_ROOT}/common/src/types.cpp"
    "${ASTRA_ROOT}/common/src/scope.cpp"
    "${ASTRA_ROOT}/common/src/${astra_platform}/clock.cpp"
    "${ASTRA_ROOT}/common/src/${astra_platform}/random.cpp"
    "${ASTRA_ROOT}/common/src/${astra_platform}/signals.cpp")
target_link_libraries(astra_platform PUBLIC platform_options)
if(BUILD_TESTING)
    foreach(name IN ITEMS clock platform)
        add_executable("astra_${name}_test" "${ASTRA_ROOT}/common/tests/${name}_test.cpp")
        target_include_directories("astra_${name}_test" PRIVATE "${ASTRA_ROOT}/common/src" "${ASTRA_ROOT}/common/tests")
        target_link_libraries("astra_${name}_test" PRIVATE astra_platform)
        add_test(NAME "native_${name}" COMMAND "astra_${name}_test")
        set_tests_properties("native_${name}" PROPERTIES TIMEOUT 30)
    endforeach()
endif()
