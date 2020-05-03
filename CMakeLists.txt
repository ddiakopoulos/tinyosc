cmake_minimum_required(VERSION 3.10)

include_guard()
project(tinyosc CXX)

set(TINYOSC_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(CMAKE_DEBUG_POSTFIX _d)

#------------------------------------------------------------------------------
# tinyosc static lib

file(GLOB tinyosc_inc "${TINYOSC_ROOT}/*.hpp")
set(tinyosc_src "${TINYOSC_ROOT}/tinyosc.cpp")

add_library(libtinyosc STATIC ${tinyosc_inc} ${tinyosc_src})
set_target_properties(libtinyosc PROPERTIES LINKER_LANGUAGE CXX)
target_compile_definitions(libtinyosc PRIVATE ${TINYOSC_DEFS})
target_link_libraries(libtinyosc PUBLIC ${TINYOSC_LIBS})

if(WIN32)
    # Arch AVX is problematic for many users, so disable it until
    # some reasonable strategy (a separate AVX target?) is determined
    #target_compile_options(${proj} PRIVATE /arch:AVX /Zi)
    target_compile_options(libtinyosc PRIVATE /Zi)
elseif(APPLE)
elseif(UNIX)
    target_compile_options(libtinyosc PRIVATE -fPIC)
endif()

source_group(tinyosc/include FILES ${tinyosc_inc})
source_group(tinyosc/src FILES ${tinyosc_src})
install(FILES ${tinyosc_inc} DESTINATION include/tinyosc)
add_library(Tiny::OSC ALIAS libtinyosc)

#------------------------------------------------------------------------------
# example tinyosc application

add_executable(tinyosc_sample "${TINYOSC_ROOT}/sample_main.cpp")
target_link_libraries(tinyosc_sample Tiny::OSC)

if(WIN32)
    # Arch AVX is problematic for many users, so disable it until
    # some reasonable strategy (a separate AVX target?) is determined
    #target_compile_options(${proj} PRIVATE /arch:AVX /Zi)
    target_compile_options(tinyosc_sample PRIVATE /Zi)
elseif(APPLE)
elseif(UNIX)
    target_compile_options(tinyosc_sample PRIVATE -fPIC)
endif()

set_property(TARGET tinyosc_sample PROPERTY FOLDER "examples")
