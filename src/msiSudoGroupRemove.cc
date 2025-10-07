/**
 * \file
 * \brief     Group remove sudo microservice.
 * \author    Chris Smeele
 * \copyright Copyright (c) 2016, 2017, 2024, Utrecht University
 */
#include "common.hh"
#include <rsGeneralAdmin.hpp>

namespace Sudo {

    int groupRemove(ruleExecInfo_t *rei,
                    msParam_t *groupName_,
                    msParam_t *policyKv_) {

        if (strcmp(groupName_->type, STR_MS_T)) {
            writeLog(__func__, LOG_ERROR, "Group name must be a string.");
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string groupName = stringFromMsp(groupName_);

        generalAdminInp_t adminParams = { };

        adminParams.arg0 = const_cast<char*>("rm");
        adminParams.arg1 = const_cast<char*>("group"); // https://github.com/irods/irods/issues/7380
        adminParams.arg2 = const_cast<char*>(groupName.c_str());
        adminParams.arg3 = const_cast<char*>(rei->uoic->rodsZone);
        adminParams.arg4 = const_cast<char*>("");
        adminParams.arg5 = const_cast<char*>("");
        adminParams.arg6 = const_cast<char*>("");
        adminParams.arg7 = const_cast<char*>("");
        adminParams.arg8 = const_cast<char*>("");
        adminParams.arg9 = const_cast<char*>("");

        return sudo(rei, [&]() { return rsGeneralAdmin(rei->rsComm, &adminParams); });
    }
}

extern "C" {
    int msiSudoGroupRemove(msParam_t *groupName_,
                           msParam_t *policyKv_,
                           ruleExecInfo_t *rei) {

        return Sudo::policify("SudoGroupRemove",
                              Sudo::groupRemove,
                              rei,
                              groupName_,
                              policyKv_);
    }

    irods::ms_table_entry *plugin_factory() {

        irods::ms_table_entry *msvc = new irods::ms_table_entry(2);

        msvc->add_operation("msiSudoGroupRemove",
                            std::function<decltype(msiSudoGroupRemove)>(msiSudoGroupRemove));
        return msvc;
    }
}
