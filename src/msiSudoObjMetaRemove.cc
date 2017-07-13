/**
 * \file
 * \brief     Object metadata remove sudo microservice.
 * \author    Chris Smeele
 * \copyright Copyright (c) 2016, 2017, Utrecht University. All rights reserved.
 */
#include "common.hh"
#include <rsModAVUMetadata.hpp>

namespace Sudo {

    int objMetaRemove(ruleExecInfo_t *rei,
                      msParam_t *objName_,
                      msParam_t *objType_,
                      msParam_t *wildcards_,
                      msParam_t *attribute_,
                      msParam_t *value_,
                      msParam_t *unit_,
                      msParam_t *policyKv_) {

        if (strcmp(objName_->type, STR_MS_T)) {
            writeLog(__func__, LOG_ERROR, "Object name must be a string.");
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string objName = stringFromMsp(objName_);

        if (strcmp(objType_->type, STR_MS_T)) {
            writeLog(__func__, LOG_ERROR, "Object type must be a string.");
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string objType = stringFromMsp(objType_);

        bool wildcards = false;

        if (!strcmp(wildcards_->type, STR_MS_T)) {

            const std::string wildcardsStr = stringFromMsp(wildcards_);
            if (wildcardsStr == "wildcards" || wildcardsStr == "1") {
                wildcards = true;
            } else if (wildcardsStr == "0" || !wildcardsStr.length()) {
                wildcards = false;
            }
        } else {
            writeLog(__func__, LOG_ERROR, "Wildcards flag must be a string (\"wildcards\", or empty).");
            return SYS_INVALID_INPUT_PARAM;
        }

        if (strcmp(attribute_->type, STR_MS_T)) {
            writeLog(__func__, LOG_ERROR, "Attribute must be a string.");
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string attribute = stringFromMsp(attribute_);

        if (strcmp(value_->type, STR_MS_T)) {
            writeLog(__func__, LOG_ERROR, "Value must be a string.");
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string value = stringFromMsp(value_);

        if (strcmp(unit_->type, STR_MS_T)) {
            writeLog(__func__, LOG_ERROR, "Unit must be a string.");
            return SYS_INVALID_INPUT_PARAM;
        }
        const std::string unit = stringFromMsp(unit_);

        if (!wildcards && value.empty()) {
            // We must be able to set the value to '%'.
            writeLog(__func__, LOG_ERROR, "Value may not be empty when wildcards are disabled.");
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

        return sudo(rei, [&]() { return rsModAVUMetadata(rei->rsComm, &modAvuParams); });
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
                              Sudo::objMetaRemove,
                              rei,
                              objName_,
                              objType_,
                              wildcards_,
                              attribute_,
                              value_,
                              unit_,
                              policyKv_);
    }

    irods::ms_table_entry *plugin_factory() {

        irods::ms_table_entry *msvc = new irods::ms_table_entry(7);

        msvc->add_operation("msiSudoObjMetaRemove",
                            std::function<decltype(msiSudoObjMetaRemove)>(msiSudoObjMetaRemove));
        return msvc;
    }
}
