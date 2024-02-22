# Find header location of Niels Lohmann's JSON library
#
# Output variable: JSON_INCLUDE_DIRS - the N. Lohmann JSON include directory

set(JSON_SEARCH_PATH "/opt/irods-externals")

# Recursively search for the header file
file(GLOB_RECURSE JSON_HEADER "${JSON_SEARCH_PATH}/json*/include/json.hpp")

# If the header file is found, set JSON_INCLUDE_DIRS to its full path
if(JSON_HEADER)
    get_filename_component(JSON_INCLUDE_DIR "${JSON_HEADER}" DIRECTORY)
    set(JSON_INCLUDE_DIRS ${JSON_INCLUDE_DIR})
else()
    message(FATAL_ERROR "json.hpp header file not found in ${JSON_SEARCH_PATH}")
endif()
