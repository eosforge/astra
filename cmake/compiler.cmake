# Compile actual syntax requirements; /std:c++latest alone is not a capability claim.
include(CheckCXXSourceCompiles)
function(astra_capabilities)
    # Probe the compiler's latest mode even when CMake has no CXX26 flag mapping yet.
    # This function scope leaves the production target's required C++26 setting intact.
    unset(CMAKE_CXX_STANDARD)
    set(CMAKE_REQUIRED_FLAGS "/std:c++latest /permissive- /utf-8 /EHsc")
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
    # Clear cached answers because a toolchain update must rerun capability detection.
    unset(astra_reflection CACHE)
    check_cxx_source_compiles([=[
#include <meta>
#include <array>
struct Tag { int value; };
struct Item { [[=Tag{7}]] int value; };
constexpr auto fields = std::define_static_array(std::meta::nonstatic_data_members_of(^^Item, std::meta::access_context::current()));
consteval int inspect() {
    Item item{3};
    int result = 0;
    template for (constexpr auto field : fields) {
        result += item.[:field:] + std::meta::extract<Tag>(std::meta::annotations_of(field)[0]).value;
    }
    return result;
}
static_assert(inspect() == 10);
]=] astra_reflection)
    unset(astra_contracts CACHE)
    check_cxx_source_compiles([=[
int check(int value) pre(value >= 0) post(result: result >= 0) {
    contract_assert(value >= 0);
    return value;
}
]=] astra_contracts)
endfunction()
astra_capabilities()
if(NOT astra_reflection OR NOT astra_contracts)
    message(FATAL_ERROR "Required C++26 capabilities missing: reflection/annotations/expansion=${astra_reflection}, contracts=${astra_contracts}. See CMakeFiles/CMakeConfigureLog.yaml. No standard or contract downgrade is allowed.")
endif()
# Syntax support is necessary but does not prove runtime enforcement or STL hardening.
message(STATUS "C++26 syntax probes compiled; contract enforcement and runtime qualification are still required")
