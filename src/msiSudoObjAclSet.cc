/**
 * \file
 * \brief     Object ACL set sudo microservice.
 * \author    Chris Smeele
 * \copyright Copyright (c) 2016, 2017, Utrecht University
 */
#include "common.hh"
#include <rsModAccessControl.hpp>

namespace Sudo {

    int objAclSet(ruleExecInfo_t *rei,
                  msParam_t *recursive_,
                  msParam_t *accessLevel_,
                  msParam_t *otherName_,
                  msParam_t *objPath_,
                  msParam_t *policyKv_) {

        bool recursive = false;

        if (!strcmp(recursive_->type, STR_MS_T)) {

            const std::string recursiveStr = stringFromMsp(recursive_);
            if (recursiveStr == "recursive") {
                recursive = true;
            } else if (!recursiveStr.length()) {
                recursive = false;
            } else {
                writeLog(__func__, LOG_ERROR, "Recursive flag must be a string (\"recursive\", or empty).");
                return SYS_INVALID_INPUT_PARAM;
            }
        } else {
            writeLog(__func__, LOG_ERROR, "Recursive flag must be a string (\"recursive\", or empty).");
            return SYS_INVALID_INPUT_PARAM;
        }

        if (strcmp(accessLevel_->type, STR_MS_T)) {
            writeLog(__func__, LOG_ERROR, "Access level must be a string.");
            return SYS_INVALID_INPUT_PARAM;
        }

        std::string accessLevel = stringFromMsp(accessLevel_);
        if (accessLevel != "null"
            && accessLevel != "read"
            && accessLevel != "write"
            && accessLevel != "own"
            && accessLevel != "inherit"
            && accessLevel != "noinherit") {

            writeLog(__func__, LOG_ERROR, "Access level must be one of (null|read|write|own|inherit|noinherit).");
            return SYS_INVALID_INPUT_PARAM;
        }

        // Apply the '-M' admin mode flag by prefixing the access level with 'admin:'.
        accessLevel.insert(0, MOD_ADMIN_MODE_PREFIX);

        if (strcmp(otherName_->type, STR_MS_T)) {
            writeLog(__func__, LOG_ERROR, "Other name must be a string.");
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string otherUserStr = stringFromMsp(otherName_);

        std::string otherName, otherZone;
        std::tie(otherName, otherZone) = splitUserZone(otherUserStr, rei);

        if (otherName.length() && accessLevel.find("inherit") != std::string::npos) {
            // "inherit" or "noinherit" was specified but a user name
            // was given as well. Inheritance is not user-specific.
            writeLog(__func__, LOG_ERROR, "When specifying inheritance, the other name must be an empty string.");
            return SYS_INVALID_INPUT_PARAM;
        }

        if (strcmp(objPath_->type, STR_MS_T)) {
            writeLog(__func__, LOG_ERROR, "Object path must be a string.");
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string objPath = stringFromMsp(objPath_);

        modAccessControlInp_t modAcParams = { };
        modAcParams.recursiveFlag = recursive;
        modAcParams.accessLevel   = const_cast<char*>(accessLevel.c_str());
        modAcParams.userName      = const_cast<char*>(otherName.c_str());
        modAcParams.zone          = const_cast<char*>(otherZone.c_str());
        modAcParams.path          = const_cast<char*>(objPath.c_str());

        return sudo(rei, [&]() { return rsModAccessControl(rei->rsComm, &modAcParams); });
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
                              Sudo::objAclSet,
                              rei,
                              recursive_,
                              accessLevel_,
                              otherName_,
                              objPath_,
                              policyKv_);
    }

    irods::ms_table_entry *plugin_factory() {

        irods::ms_table_entry *msvc = new irods::ms_table_entry(5);

        msvc->add_operation("msiSudoObjAclSet",
                            std::function<decltype(msiSudoObjAclSet)>(msiSudoObjAclSet));
        return msvc;
    }
}
