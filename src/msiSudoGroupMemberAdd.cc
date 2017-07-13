/**
 * \file
 * \brief     Group member add sudo microservice.
 * \author    Chris Smeele
 * \copyright Copyright (c) 2016, 2017, Utrecht University. All rights reserved.
 */
#include "common.hh"
#include <rsGeneralAdmin.hpp>

namespace Sudo {

    int groupMemberAdd(ruleExecInfo_t *rei,
                       msParam_t *groupName_,
                       msParam_t *userName_,
                       msParam_t *policyKv_) {

        if (strcmp(groupName_->type, STR_MS_T)) {
            writeLog(__func__, LOG_ERROR, "Group name must be a string.");
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string groupName = stringFromMsp(groupName_);

        if (strcmp(userName_->type, STR_MS_T)) {
            writeLog(__func__, LOG_ERROR, "User name must be a string.");
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string userStr = stringFromMsp(userName_);

        std::string userName, zoneName;
        std::tie(userName, zoneName) = splitUserZone(userStr, rei);

        generalAdminInp_t adminParams = { };

        adminParams.arg0 = const_cast<char*>("modify");
        adminParams.arg1 = const_cast<char*>("group");
        adminParams.arg2 = const_cast<char*>(groupName.c_str());
        adminParams.arg3 = const_cast<char*>("add");
        adminParams.arg4 = const_cast<char*>(userName.c_str());
        adminParams.arg5 = const_cast<char*>(zoneName.c_str());
        adminParams.arg6 = const_cast<char*>("");
        adminParams.arg7 = const_cast<char*>("");
        adminParams.arg8 = const_cast<char*>("");
        adminParams.arg9 = const_cast<char*>("");

        return sudo(rei, [&]() { return rsGeneralAdmin(rei->rsComm, &adminParams); });
    }
}

extern "C" {
    int msiSudoGroupMemberAdd(msParam_t *groupName_,
                              msParam_t *userName_,
                              msParam_t *policyKv_,
                              ruleExecInfo_t *rei) {

        return Sudo::policify("SudoGroupMemberAdd",
                              Sudo::groupMemberAdd,
                              rei,
                              groupName_,
                              userName_,
                              policyKv_);
    }

    irods::ms_table_entry *plugin_factory() {

        irods::ms_table_entry *msvc = new irods::ms_table_entry(3);

        msvc->add_operation("msiSudoGroupMemberAdd",
                            std::function<decltype(msiSudoGroupMemberAdd)>(msiSudoGroupMemberAdd));
        return msvc;
    }
}
