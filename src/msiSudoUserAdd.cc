/**
 * \file
 * \brief     User add sudo microservice.
 * \author    Chris Smeele
 * \copyright Copyright (c) 2016, Utrecht University. All rights reserved.
 */
#include "common.hh"
#include <generalAdmin.h>
#include <modAVUMetadata.h>

namespace Sudo {
    int userAdd(ruleExecInfo_t *rei,
                msParam_t *userName_,
                msParam_t *initialMetaAttr_,
                msParam_t *initialMetaValue_,
                msParam_t *initialMetaUnit_,
                msParam_t *policyKv_) {

        if (std::string(userName_->type) != STR_MS_T) {
            std::cerr << __FILE__ << ": User name must be a string.\n";
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string userStr = parseMspForStr(userName_);

        if (std::string(initialMetaAttr_->type) != STR_MS_T) {
            std::cerr << __FILE__ << ": Initial attribute must be a string.\n";
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string initialMetaAttr = parseMspForStr(initialMetaAttr_);

        if (std::string(initialMetaValue_->type) != STR_MS_T) {
            std::cerr << __FILE__ << ": Initial value must be a string.\n";
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string initialMetaValue = parseMspForStr(initialMetaValue_);

        if (std::string(initialMetaUnit_->type) != STR_MS_T) {
            std::cerr << __FILE__ << ": Initial unit must be a string.\n";
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string initialMetaUnit = parseMspForStr(initialMetaUnit_);

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

        int status = sudo(rei, std::bind<int>(rsGeneralAdmin, rei->rsComm, &adminParams));

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

            status = sudo(rei, std::bind<int>(rsModAVUMetadata, rei->rsComm, &modAvuParams));
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
                              Sudo::msi_5param_t(Sudo::userAdd),
                              rei,
                              userName_,
                              initialMetaAttr_,
                              initialMetaValue_,
                              initialMetaUnit_,
                              policyKv_);
    }

    irods::ms_table_entry* plugin_factory() {

        irods::ms_table_entry* msvc = new irods::ms_table_entry(5);

        // C symbol, rule symbol.
        msvc->add_operation("msiSudoUserAdd",
                            "msiSudoUserAdd");
        return msvc;
    }
}
