/**
 * \file
 * \brief     Group add sudo microservice.
 * \author    Chris Smeele
 * \copyright Copyright (c) 2016, Utrecht University. All rights reserved.
 */
#include "common.hh"
#include <generalAdmin.h>
#include <modAVUMetadata.h>

namespace Sudo {
    int groupAdd(ruleExecInfo_t *rei,
                 msParam_t *groupName_,
                 msParam_t *initialMetaAttr_,
                 msParam_t *initialMetaValue_,
                 msParam_t *initialMetaUnit_,
                 msParam_t *policyKv_) {

        if (std::string(groupName_->type) != STR_MS_T) {
            std::cerr << __FILE__ << ": Group name must be a string.\n";
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string groupName = stringFromMsp(groupName_);

        if (std::string(initialMetaAttr_->type) != STR_MS_T) {
            std::cerr << __FILE__ << ": Initial attribute must be a string.\n";
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string initialMetaAttr = stringFromMsp(initialMetaAttr_);

        if (std::string(initialMetaValue_->type) != STR_MS_T) {
            std::cerr << __FILE__ << ": Initial value must be a string.\n";
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string initialMetaValue = stringFromMsp(initialMetaValue_);

        if (std::string(initialMetaUnit_->type) != STR_MS_T) {
            std::cerr << __FILE__ << ": Initial unit must be a string.\n";
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string initialMetaUnit = stringFromMsp(initialMetaUnit_);

        // NB: XXX: Icommands and other iRODS sources deem it safe
        // to pass const pointers in non-const pointer fields in
        // all *Inp_t structs. However ugly, we follow that
        // example. It appears guaranteed that the contents of the
        // struct will not be modified.

        generalAdminInp_t adminParams = { };

        adminParams.arg0 = const_cast<char*>("add");
        adminParams.arg1 = const_cast<char*>("user");
        adminParams.arg2 = const_cast<char*>(groupName.c_str());
        adminParams.arg3 = const_cast<char*>("rodsgroup");
        adminParams.arg4 = const_cast<char*>(rei->uoic->rodsZone);
        adminParams.arg5 = const_cast<char*>("");
        adminParams.arg6 = const_cast<char*>("");
        adminParams.arg7 = const_cast<char*>("");
        adminParams.arg8 = const_cast<char*>("");
        adminParams.arg9 = const_cast<char*>("");

        // return sudo(rei, [&]() -> int {
        //     return rsUserAdmin(rei->rsComm, &adminParams);
        // });
        int status = sudo(rei, std::bind<int>(rsGeneralAdmin, rei->rsComm, &adminParams));

        if (status)
            return status;

        if (!initialMetaAttr.empty() && !initialMetaValue.empty()) {
            modAVUMetadataInp_t modAvuParams = { };
            modAvuParams.arg0 = const_cast<char*>("add");
            modAvuParams.arg1 = const_cast<char*>("-u");
            modAvuParams.arg2 = const_cast<char*>(groupName.c_str());
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
    int msiSudoGroupAdd(msParam_t *groupName_,
                        msParam_t *initialMetaAttr_,
                        msParam_t *initialMetaValue_,
                        msParam_t *initialMetaUnit_,
                        msParam_t *policyKv_,
                        ruleExecInfo_t *rei) {

        return Sudo::policify("SudoGroupAdd",
                              Sudo::msi_5param_t(Sudo::groupAdd),
                              rei,
                              groupName_,
                              initialMetaAttr_,
                              initialMetaValue_,
                              initialMetaUnit_,
                              policyKv_);
    }

    irods::ms_table_entry* plugin_factory() {

        irods::ms_table_entry* msvc = new irods::ms_table_entry(5);

        // C symbol, rule symbol.
        msvc->add_operation("msiSudoGroupAdd",
                            "msiSudoGroupAdd");
        return msvc;
    }
}
