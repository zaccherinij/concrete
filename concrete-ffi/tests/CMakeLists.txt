project(ProjectName)

cmake_minimum_required(VERSION 3.21)

set(CONCRETE_FFI_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/../../target/release/")

include_directories(${CONCRETE_FFI_RELEASE})
add_library(Concrete STATIC IMPORTED)
set_target_properties(Concrete PROPERTIES IMPORTED_LOCATION ${CONCRETE_FFI_RELEASE}/libconcrete_ffi.a )

file(GLOB TEST_CASES test_*.c)
foreach (testsourcefile ${TEST_CASES})
    get_filename_component(testname ${testsourcefile} NAME_WLE)
    get_filename_component(groupname ${testsourcefile} DIRECTORY)
    add_executable(${testname} ${testsourcefile})
    add_test(
            NAME ${testname}
            COMMAND ${testname}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/Testing
    )
    target_link_libraries(${testname} LINK_PUBLIC Concrete m dl pthread)
endforeach (testsourcefile ${TEST_CASES})