/**
 * \file
 * \brief     Object metadata remove sudo microservice.
 * \author    Chris Smeele
 * \copyright Copyright (c) 2016, Utrecht University. All rights reserved.
 */
#include "common.hh"
#include <modAVUMetadata.h>

namespace Sudo {
    int objMetaRemove(ruleExecInfo_t *rei,
                      msParam_t *objName_,
                      msParam_t *objType_,
                      msParam_t *wildcards_,
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

        if (std::string(wildcards_->type) != INT_MS_T) {
            std::cerr << __FILE__ << ": Wildcards flag must be an int (0|1).\n";
            return SYS_INVALID_INPUT_PARAM;
        }
        bool wildcards = parseMspForPosInt(wildcards_) > 0;

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

        if (!wildcards && value.empty()) {
            // We must be able to set the value to '%'.
            std::cerr << __FILE__ << ": Value may not be empty when wildcards are disabled.\n";
            return SYS_INVALID_INPUT_PARAM;
            // This does not apply to the unit field, which can be omitted (left empty).
        }

        modAVUMetadataInp_t modAvuParams = { };

        if (wildcards)
            modAvuParams.arg0 = const_cast<char*>("rmw");
        else
            modAvuParams.arg0 = const_cast<char*>("rm");

        modAvuParams.arg1 = const_cast<char*>(objType.c_str());
        modAvuParams.arg2 = const_cast<char*>(objName.c_str());
        modAvuParams.arg3 = const_cast<char*>(attribute.c_str());

        if (wildcards && value.empty())
            modAvuParams.arg4 = const_cast<char*>("%");
        else
            modAvuParams.arg4 = const_cast<char*>(value.c_str());

        modAvuParams.arg5 = const_cast<char*>(unit.c_str());
        modAvuParams.arg6 = const_cast<char*>("");
        modAvuParams.arg7 = const_cast<char*>("");
        modAvuParams.arg8 = const_cast<char*>("");
        modAvuParams.arg9 = const_cast<char*>("");

        return sudo(rei, std::bind<int>(rsModAVUMetadata, rei->rsComm, &modAvuParams));
        // return rsModAVUMetadata(rei->rsComm, &modAvuParams);
    }
}

extern "C" {
    
    int msiSudoObjMetaRemove(msParam_t *objName_,
                             msParam_t *objType_,
                             msParam_t *wildcards_,
                             msParam_t *attribute_,
                             msParam_t *value_,
                             msParam_t *unit_,
                             msParam_t *policyKv_,
                             ruleExecInfo_t *rei) {

        return Sudo::policify("SudoObjMetaRemove",
                              Sudo::msi_7param_t(Sudo::objMetaRemove),
                              rei,
                              objName_,
                              objType_,
                              wildcards_,
                              attribute_,
                              value_,
                              unit_,
                              policyKv_);
    }

    irods::ms_table_entry* plugin_factory() {

        irods::ms_table_entry* msvc = new irods::ms_table_entry(7);

        // C symbol, rule symbol.
        msvc->add_operation("msiSudoObjMetaRemove",
                            "msiSudoObjMetaRemove");
        return msvc;
    }
}
