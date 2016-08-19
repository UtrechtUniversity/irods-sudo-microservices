/**
 * \file
 * \brief     Object ACL set sudo microservice.
 * \author    Chris Smeele
 * \copyright Copyright (c) 2016, Utrecht University. All rights reserved.
 */
#include "common.hh"

namespace Sudo {
    int objAclSet(ruleExecInfo_t *rei,
                  msParam_t *recursive_,
                  msParam_t *accessLevel_,
                  msParam_t *otherName_,
                  msParam_t *objPath_,
                  msParam_t *policyKv_) {

        bool recursive = false;

        if (std::string(recursive_->type) == INT_MS_T) {
            recursive = parseMspForPosInt(recursive_) > 0;
        } else if (std::string(recursive_->type) == STR_MS_T) {

            // Accept a string for msiSetACL compatibility.
            const std::string recursiveStr = parseMspForStr(recursive_);
            if (recursiveStr == "recursive" || recursiveStr == "1") {
                recursive = true;
            } else if (recursiveStr == "default" || recursiveStr == "0") {
                recursive = false;
            } else {
                std::cerr << __FILE__ << ": Recursive flag must be an integer (1 = recurse, 0 = do not recurse).\n";
                return SYS_INVALID_INPUT_PARAM;
            }
        } else {
            std::cerr << __FILE__ << ": Recursive flag must be an integer (1 = recurse, 0 = do not recurse).\n";
            return SYS_INVALID_INPUT_PARAM;
        }

        if (std::string(accessLevel_->type) != STR_MS_T) {
            std::cerr << __FILE__ << ": Access level must be a string.\n";
            return SYS_INVALID_INPUT_PARAM;
        }

        std::string accessLevel = parseMspForStr(accessLevel_);
        if (accessLevel != "null"
            && accessLevel != "read"
            && accessLevel != "write"
            && accessLevel != "own"
            && accessLevel != "inherit"
            && accessLevel != "noinherit") {

            std::cerr << __FILE__ << ": Access level must be one of (null|read|write|own|inherit|noinherit).\n";
            return SYS_INVALID_INPUT_PARAM;
        }

        // Apply the '-M' admin mode flag by prefixing the access level with 'admin:'.
        accessLevel.insert(0, MOD_ADMIN_MODE_PREFIX);

        if (std::string(otherName_->type) != STR_MS_T) {
            std::cerr << __FILE__ << ": Other name must be a string.\n";
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string otherUserStr = parseMspForStr(otherName_);

        std::string otherName, otherZone;
        std::tie(otherName, otherZone) = splitUserZone(otherUserStr, rei);

        if (otherName.length() && accessLevel.find("inherit") != std::string::npos) {
            // "inherit" or "noinherit" was specified but a user name
            // was given as well. Inheritance is not user-specific.
            std::cerr << __FILE__ << ": When specifying inheritance, the other name must be an empty string.\n";
            return SYS_INVALID_INPUT_PARAM;
        }

        if (std::string(objPath_->type) != STR_MS_T) {
            std::cerr << __FILE__ << ": Object path must be a string.\n";
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string objPath = parseMspForStr(objPath_);

        modAccessControlInp_t modAcParams = { };
        modAcParams.recursiveFlag = recursive;
        modAcParams.accessLevel   = const_cast<char*>(accessLevel.c_str());
        modAcParams.userName      = const_cast<char*>(otherName.c_str());
        modAcParams.zone          = const_cast<char*>(otherZone.c_str());
        modAcParams.path          = const_cast<char*>(objPath.c_str());

        return sudo(rei, std::bind<int>(rsModAccessControl, rei->rsComm, &modAcParams));
    }
}

extern "C" {
    int msiSudoObjAclSet(msParam_t *recursive_,
                         msParam_t *accessLevel_,
                         msParam_t *otherName_,
                         msParam_t *objPath_,
                         msParam_t *policyKv_,
                         ruleExecInfo_t *rei) {

        return Sudo::policify("SudoObjAclSet",
                              Sudo::msi_5param_t(Sudo::objAclSet),
                              rei,
                              recursive_,
                              accessLevel_,
                              otherName_,
                              objPath_,
                              policyKv_);
    }

    irods::ms_table_entry* plugin_factory() {

        irods::ms_table_entry* msvc = new irods::ms_table_entry(5);

        // C symbol, rule symbol.
        msvc->add_operation("msiSudoObjAclSet",
                            "msiSudoObjAclSet");
        return msvc;
    }
}
