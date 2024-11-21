cmake_minimum_required(VERSION 3.21.4 FATAL_ERROR)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/CMakeModules")

find_package(IRODS 4.3.3 EXACT REQUIRED)

message(STATUS "Building for irods-server version ${IRODS_VERSION}")

# Note: Microservices for iRODS >=4.2 need to be built with the compiler and
# standard libarary provided by iRODS-externals packages.
# The following packages need to be installed to build the sudo microservices:
#
# irods-externals-cmake3.21.4-0
# irods-externals-clang13.0.0-0
# irods-externals-json3.10.4-0
# irods-externals-fmt8.1.1-0

set(CMAKE_CXX_COMPILER ${IRODS_EXTERNALS_FULLPATH_CLANG}/bin/clang++)

project(sudo-msis CXX)

add_compile_options(-std=c++17
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

set(BOOST_ROOT "${IRODS_EXTERNALS_FULLPATH_BOOST}")
find_package(Boost REQUIRED)
include_directories(SYSTEM ${Boost_INCLUDE_DIR})
link_libraries(${Boost_LIBRARIES})

find_package(fmt "8.1.1"
  HINTS "${IRODS_EXTERNALS_FULLPATH_FMT}")
link_libraries(fmt::fmt)

find_package(nlohmann_json "3.10.4" REQUIRED)
link_libraries(nlohmann_json::nlohmann_json)

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

# Packaging {{{

# Make sure your umask is set correctly when packaging:
# The default umask is 0002, which results in e.g. rwxrwxr-x
# directories within generated RPMs, which will conflict with existing
# directories from irods packages, which will be rwxr-xr-x.
# To create packages, set your umask to 0022 first (`umask 0022`).

set(IRODS_MSVC_VERSION "1.0.0")

execute_process(
  COMMAND "python3" "-c" "from __future__ import print_function; import distro; print(distro.id(), end='')"
  RESULT_VARIABLE IRODS_EXECUTE_PROCESS_RESULT_LINUX_DISTRIBUTION_NAME
  OUTPUT_VARIABLE IRODS_LINUX_DISTRIBUTION_NAME
)

message(STATUS "Found Linux distro ${IRODS_LINUX_DISTRIBUTION_NAME}")

# Determine which type of package should be generated
if (IRODS_LINUX_DISTRIBUTION_NAME MATCHES "^(ubuntu|debian)$")
    set(CPACK_GENERATOR "DEB")
    set(CPACK_PACKAGE_VERSION "${IRODS_VERSION}-${IRODS_MSVC_VERSION}")
elseif (IRODS_LINUX_DISTRIBUTION_NAME STREQUAL "almalinux")
    set(CPACK_GENERATOR "RPM")
    set(CPACK_PACKAGE_VERSION "${IRODS_VERSION}_${IRODS_MSVC_VERSION}")
endif()


set(CPACK_MONOLITHIC_INSTALL 1)
set(CPACK_CMAKE_GENERATOR "Unix Makefiles")
set(CPACK_PACKAGE_NAME "irods-sudo-microservices")
set(CPACK_PACKAGE_VENDOR "Utrecht University <fbyoda@uu.nl>")
set(CPACK_PACKAGE_CONTACT "Utrecht University <fbyoda@uu.nl>")
#set(CPACK_PACKAGE_VERSION_MAJOR "1")
#set(CPACK_PACKAGE_VERSION_MINOR "0")
#set(CPACK_PACKAGE_VERSION_PATCH "0")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/package/description.txt")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "iRODS microservices for policy-enhanced administrative operations")

set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING.LESSER")
set(CPACK_RESOURCE_FILE_README  "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

set(CPACK_RPM_PACKAGE_RELEASE "1")
set(CPACK_RPM_PACKAGE_LICENSE "LGPLv3")
set(CPACK_RPM_PACKAGE_REQUIRES "irods-server = ${IRODS_VERSION}")
set(CPACK_RPM_PACKAGE_URL "https://github.com/UtrechtUniversity/irods-sudo-microservices")
set(CPACK_RPM_CHANGELOG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/package/changelog.txt")
set(CPACK_RPM_PACKAGE_AUTOREQ 0)
set(CPACK_RPM_PACKAGE_AUTOPROV 0)

# NOTE: We run into an issue with permissions on /etc/irods:
# - The irods-setup.py sets ownership to irods:irods.
# - We'd like to leave the permissions&ownership of this directory alone, but
#   CMake doesn't let us.
# - As a compromise we reset ownership to irods:irods using a post-install script.
#   (currently only implemented in the RPM)
#
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/package/postinst.sh")

set(CPACK_DEBIAN_PACKAGE_DEPENDS "irods-server ( = ${IRODS_VERSION}-0~noble )")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/UtrechtUniversity/irods-sudo-microservices")
set(CPACK_DEBIAN_PACKAGE_SECTION "contrib/science")

set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_RPM_PACKAGE_RELEASE}")

include(CPack)

# }}}
