/**
 * \file
 * \brief     Object metadata add sudo microservice.
 * \author    Chris Smeele
 * \copyright Copyright (c) 2016, Utrecht University. All rights reserved.
 */
#include "common.hh"
#include <modAVUMetadata.h>

namespace Sudo {
    int objMetaAdd(ruleExecInfo_t *rei,
                   msParam_t *objName_,
                   msParam_t *objType_,
                   msParam_t *attribute_,
                   msParam_t *value_,
                   msParam_t *unit_,
                   msParam_t *policyKv_) {

        if (std::string(objName_->type) != STR_MS_T) {
            std::cerr << __FILE__ << ": Object name must be a string.\n";
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string objName = stringFromMsp(objName_);

        if (std::string(objType_->type) != STR_MS_T) {
            std::cerr << __FILE__ << ": Object type must be a string.\n";
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string objType = stringFromMsp(objType_);

        if (std::string(attribute_->type) != STR_MS_T) {
            std::cerr << __FILE__ << ": Attribute must be a string.\n";
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string attribute = stringFromMsp(attribute_);

        if (std::string(value_->type) != STR_MS_T) {
            std::cerr << __FILE__ << ": Value must be a string.\n";
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string value = stringFromMsp(value_);

        if (std::string(unit_->type) != STR_MS_T) {
            std::cerr << __FILE__ << ": Unit must be a string.\n";
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string unit = stringFromMsp(unit_);

        modAVUMetadataInp_t modAvuParams = { };
        modAvuParams.arg0 = const_cast<char*>("add");
        modAvuParams.arg1 = const_cast<char*>(objType.c_str());
        modAvuParams.arg2 = const_cast<char*>(objName.c_str());
        modAvuParams.arg3 = const_cast<char*>(attribute.c_str());
        modAvuParams.arg4 = const_cast<char*>(value.c_str());
        modAvuParams.arg5 = const_cast<char*>(unit.c_str());
        modAvuParams.arg6 = const_cast<char*>("");
        modAvuParams.arg7 = const_cast<char*>("");
        modAvuParams.arg8 = const_cast<char*>("");
        modAvuParams.arg9 = const_cast<char*>("");

        return sudo(rei, std::bind<int>(rsModAVUMetadata, rei->rsComm, &modAvuParams));
    }
}

extern "C" {
    
    int msiSudoObjMetaAdd(msParam_t *objName_,
                          msParam_t *objType_,
                          msParam_t *attribute_,
                          msParam_t *value_,
                          msParam_t *unit_,
                          msParam_t *policyKv_,
                          ruleExecInfo_t *rei) {

        return Sudo::policify("SudoObjMetaAdd",
                              Sudo::msi_6param_t(Sudo::objMetaAdd),
                              rei,
                              objName_,
                              objType_,
                              attribute_,
                              value_,
                              unit_,
                              policyKv_);
    }

    irods::ms_table_entry* plugin_factory() {

        irods::ms_table_entry* msvc = new irods::ms_table_entry(6);

        // C symbol, rule symbol.
        msvc->add_operation("msiSudoObjMetaAdd",
                            "msiSudoObjMetaAdd");
        return msvc;
    }
}
