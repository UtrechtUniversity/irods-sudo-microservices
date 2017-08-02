/**
 * \file
 * \brief     User add sudo microservice.
 * \author    Chris Smeele
 * \copyright Copyright (c) 2016, 2017, Utrecht University
 */
#include "common.hh"
#include <rsGeneralAdmin.hpp>
#include <rsModAVUMetadata.hpp>

namespace Sudo {

    int userAdd(ruleExecInfo_t *rei,
                msParam_t *userName_,
                msParam_t *initialMetaAttr_,
                msParam_t *initialMetaValue_,
                msParam_t *initialMetaUnit_,
                msParam_t *policyKv_) {

        if (strcmp(userName_->type, STR_MS_T)) {
            writeLog(__func__, LOG_ERROR, "User name must be a string.");
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string userStr = stringFromMsp(userName_);

        if (strcmp(initialMetaAttr_->type, STR_MS_T)) {
            writeLog(__func__, LOG_ERROR, "Initial attribute must be a string.");
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string initialMetaAttr = stringFromMsp(initialMetaAttr_);

        if (strcmp(initialMetaValue_->type, STR_MS_T)) {
            writeLog(__func__, LOG_ERROR, "Initial value must be a string.");
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string initialMetaValue = stringFromMsp(initialMetaValue_);

        if (strcmp(initialMetaUnit_->type, STR_MS_T)) {
            writeLog(__func__, LOG_ERROR, "Initial unit must be a string.");
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string initialMetaUnit = stringFromMsp(initialMetaUnit_);

        std::string userName, zoneName;
        std::tie(userName, zoneName) = splitUserZone(userStr, rei);

        generalAdminInp_t adminParams = { };

        adminParams.arg0 = const_cast<char*>("add");
        adminParams.arg1 = const_cast<char*>("user");
        adminParams.arg2 = const_cast<char*>(userName.c_str());
        adminParams.arg3 = const_cast<char*>("rodsuser");
        adminParams.arg4 = const_cast<char*>(zoneName.c_str());
        adminParams.arg5 = const_cast<char*>("");
        adminParams.arg6 = const_cast<char*>("");
        adminParams.arg7 = const_cast<char*>("");
        adminParams.arg8 = const_cast<char*>("");
        adminParams.arg9 = const_cast<char*>("");

        int status = sudo(rei, [&]() { return rsGeneralAdmin(rei->rsComm, &adminParams); });

        if (status)
            return status;

        if (!initialMetaAttr.empty() && !initialMetaValue.empty()) {
            modAVUMetadataInp_t modAvuParams = { };
            modAvuParams.arg0 = const_cast<char*>("add");
            modAvuParams.arg1 = const_cast<char*>("-u");
            modAvuParams.arg2 = const_cast<char*>(userName.c_str());
            modAvuParams.arg3 = const_cast<char*>(initialMetaAttr.c_str());
            modAvuParams.arg4 = const_cast<char*>(initialMetaValue.c_str());
            modAvuParams.arg5 = const_cast<char*>(initialMetaUnit.c_str());
            modAvuParams.arg6 = const_cast<char*>("");
            modAvuParams.arg7 = const_cast<char*>("");
            modAvuParams.arg8 = const_cast<char*>("");
            modAvuParams.arg9 = const_cast<char*>("");

            status = sudo(rei, [&]() { return rsModAVUMetadata(rei->rsComm, &modAvuParams); });
        }

        return status;
    }
}

extern "C" {
    int msiSudoUserAdd(msParam_t *userName_,
                       msParam_t *initialMetaAttr_,
                       msParam_t *initialMetaValue_,
                       msParam_t *initialMetaUnit_,
                       msParam_t *policyKv_,
                       ruleExecInfo_t *rei) {

        return Sudo::policify("SudoUserAdd",
                              Sudo::userAdd,
                              rei,
                              userName_,
                              initialMetaAttr_,
                              initialMetaValue_,
                              initialMetaUnit_,
                              policyKv_);
    }

    irods::ms_table_entry *plugin_factory() {

        irods::ms_table_entry *msvc = new irods::ms_table_entry(5);

        msvc->add_operation("msiSudoUserAdd",
                            std::function<decltype(msiSudoUserAdd)>(msiSudoUserAdd));
        return msvc;
    }
}
