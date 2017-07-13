cmake_minimum_required(VERSION 2.8.12)

find_package(IRODS 4.2.1 EXACT REQUIRED)

# Note: Microservices for iRODS >=4.2 need to be built with the compiler and
# standard libarary provided by iRODS-externals packages.
# The following packages need to be installed to build the sudo microservices:
#
# irods-externals-clang-runtime3.8-0
# irods-externals-clang3.8-0

set(CMAKE_CXX_COMPILER ${IRODS_EXTERNALS_FULLPATH_CLANG}/bin/clang++)

project(sudo-msis CXX)

add_compile_options(-std=c++14
                    -Os
                    -fPIC
                    -DRODS_SERVER
                    -nostdinc++
                    -Wall
                    -Wextra
                    -Wpedantic
                    -Wcast-align
                    -Wredundant-decls
                    -Wuninitialized
                    -Wconversion
                    -Wno-missing-field-initializers
                    -Wno-unused-parameter)

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -stdlib=libc++")
link_libraries(c++abi)
include_directories("${IRODS_EXTERNALS_FULLPATH_CLANG}/include/c++/v1")
include_directories("/usr/include/irods")

# Common functionalities required by all sudo msis.
add_library(sudo_common              STATIC src/common.cc)
link_libraries(sudo_common)

add_library(msiSudoUserAdd           SHARED src/msiSudoUserAdd.cc)
add_library(msiSudoUserRemove        SHARED src/msiSudoUserRemove.cc)
add_library(msiSudoGroupAdd          SHARED src/msiSudoGroupAdd.cc)
add_library(msiSudoGroupRemove       SHARED src/msiSudoGroupRemove.cc)
add_library(msiSudoGroupMemberAdd    SHARED src/msiSudoGroupMemberAdd.cc)
add_library(msiSudoGroupMemberRemove SHARED src/msiSudoGroupMemberRemove.cc)
add_library(msiSudoObjAclSet         SHARED src/msiSudoObjAclSet.cc)
add_library(msiSudoObjMetaSet        SHARED src/msiSudoObjMetaSet.cc)
add_library(msiSudoObjMetaAdd        SHARED src/msiSudoObjMetaAdd.cc)
add_library(msiSudoObjMetaRemove     SHARED src/msiSudoObjMetaRemove.cc)

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
        /usr/lib/irods/plugins/microservices)

install(FILES "policies.re"
        DESTINATION /etc/irods
        RENAME sudo-default-policies.re)
