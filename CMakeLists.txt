cmake_minimum_required(VERSION 2.6)

project(sudo-msis)

enable_testing()

set(warnings
    "-Wall"
    "-Wextra"
    "-Wall"
    "-Wextra"
    "-Wpedantic"
    "-Wcast-align"
    #"-Wmissing-declarations"
    "-Wredundant-decls"
    "-Wuninitialized"
    "-Wconversion"
    "-Wno-missing-field-initializers"
    "-Wno-unused-parameter")

set(cxxflags
    "-std=c++11"
    "-DRODS_SERVER"
    "-fPIC"
    ${warnings})

string(REGEX REPLACE ";" " " cxxflags "${cxxflags}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${cxxflags}")

string(REGEX REPLACE ";" " " ldflags "${ldflags}")
set(CMAKE_LD_FLAGS "${CMAKE_LD_FLAGS} ${ldflags}")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include
                    "/usr/include/irods")

set(common_sources
    src/common.cc)

add_library(sudo_common STATIC ${common_sources})

link_libraries(sudo_common)

add_library(msiSudoUserAdd           SHARED "src/msiSudoUserAdd.cc")
add_library(msiSudoUserRemove        SHARED "src/msiSudoUserRemove.cc")
add_library(msiSudoGroupAdd          SHARED "src/msiSudoGroupAdd.cc")
add_library(msiSudoGroupRemove       SHARED "src/msiSudoGroupRemove.cc")
add_library(msiSudoGroupMemberAdd    SHARED "src/msiSudoGroupMemberAdd.cc")
add_library(msiSudoGroupMemberRemove SHARED "src/msiSudoGroupMemberRemove.cc")
add_library(msiSudoObjAclSet         SHARED "src/msiSudoObjAclSet.cc")
add_library(msiSudoObjMetaSet        SHARED "src/msiSudoObjMetaSet.cc")
add_library(msiSudoObjMetaAdd        SHARED "src/msiSudoObjMetaAdd.cc")
add_library(msiSudoObjMetaRemove     SHARED "src/msiSudoObjMetaRemove.cc")

install(TARGETS
        msiSudoUserAdd
        msiSudoUserRemove
        msiSudoGroupAdd
        msiSudoGroupRemove
        msiSudoGroupMemberAdd
        msiSudoGroupMemberRemove
        msiSudoObjAclSet
        msiSudoObjMetaSet
        msiSudoObjMetaAdd
        msiSudoObjMetaRemove
        DESTINATION
        /var/lib/irods/plugins/microservices)
