/**
 * \file
 * \brief     Group add sudo microservice.
 * \author    Chris Smeele
 * \copyright Copyright (c) 2016, Utrecht University. All rights reserved.
 */
#include "common.hh"

namespace Sudo {

    std::tuple<std::string, std::string> splitUserZone(const std::string &userZoneStr,
                                                       const ruleExecInfo_t *rei) {
        size_t hashPos = userZoneStr.find('#');
        if (hashPos == std::string::npos) {
            // No zone name specified, take the client's zone.
            return std::make_tuple(userZoneStr, rei->uoic->rodsZone);
        } else {
            return std::make_tuple(userZoneStr.substr(0, hashPos),
                                   userZoneStr.substr(hashPos+1));
        }
    }

    int sudo(ruleExecInfo_t *rei, std::function<int()> f) {
        // Backup.
        int authBupC = rei->uoic->authInfo.authFlag;
        int authBupP = rei->uoip->authInfo.authFlag;

        // Elevate privileges.
        rei->uoic->authInfo.authFlag = LOCAL_PRIV_USER_AUTH;
        rei->uoip->authInfo.authFlag = LOCAL_PRIV_USER_AUTH;

        int ret = -1;

        try {
            // Call privileged function.
            ret = f();
        } catch (...) {
            // Restore privileges.
            rei->uoip->authInfo.authFlag = authBupP;
            rei->uoic->authInfo.authFlag = authBupC;
            throw;
        }

        rei->uoip->authInfo.authFlag = authBupP;
        rei->uoic->authInfo.authFlag = authBupC;

        return ret;
    }

    std::string stringFromMsp(msParam_t *param) {
        if (!param)
            return "null";

        const char *str = parseMspForStr(param);

        return str ? str : "null";
    }

    ParamArray &ParamArray::operator<<(const ParamParam &param) {
        char      *label = strdup(std::get<0>(param).c_str());
        msParam_t *value = std::get<1>(param);
        assert(label);
        assert(value);
        toFree.push_back(label);
        addMsParam(&array, label, param.second->type, value->inOutStruct, value->inpOutBuf);

        labels.push_back(std::get<0>(param));
        return *this;
    }

    ParamArray &ParamArray::operator<<(const StrParam &param) {
        char *label = strdup(param.first.c_str());
        char *value = strdup(param.second.c_str());
        assert(label);
        assert(value);
        toFree.push_back(label);
        toFree.push_back(value);
        addMsParamToArray(&array, label, STR_MS_T, value, NULL, 0);
        labels.push_back(param.first);
        return *this;
    }

    ParamArray &ParamArray::operator<<(const IntParam &param) {
        char *label = strdup(param.first.c_str());
        assert(label);
        addIntParamToArray(&array, label, param.second);
        labels.push_back(param.first);
        toFree.push_back(label);
        return *this;
    }

    ParamArray &ParamArray::operator<<(const std::string &param) {
        char *label = strdup(param.c_str());
        assert(label);
        addMsParamToArray(&array, label, NULL, NULL, NULL, 0);
        labels.push_back(param);
        toFree.push_back(label);
        return *this;
    }

    std::string ParamArray::getType(const std::string &label) {
        msParam_t *param = getMsParamByLabel(&array, label.c_str());

        if (param) {
            return param->type;
        } else {
            return "";
        }
    }

    std::string ParamArray::getStr(const std::string &label) {
        msParam_t *param = getMsParamByLabel(&array, label.c_str());

        if (param) {
            char *value = parseMspForStr(param);
            if (value)
                return value;
            else
                return ""; // XXX
        } else {
            return "";
        }
    }

    int ParamArray::getInt(const std::string &label) {
        msParam_t *param = getMsParamByLabel(&array, label.c_str());

        if (param)
            return parseMspForPosInt(param);
        else
            return -1;
    }

    int callRule(const std::string &ruleName, ParamArray &params, ruleExecInfo_t *rei) {
        std::string header = ruleName + "(";

        std::set<std::string> seenLabels { };
        int i = 0;

        for (auto label : params.getLabels()) {
            if (seenLabels.find(label) == seenLabels.end()) {
                seenLabels.insert(label);
                if (i++)
                    header += ',';
                header += label;
            }
        }
        header += ')';
        char *headerCopy = strdup(header.c_str());
        assert(headerCopy);

        int status = applyRuleUpdateParams(headerCopy, &params.array, rei, NO_SAVE_REI);
        // int status = applyRuleUpdateParams(headerCopy, &params.array, rei, SAVE_REI);
        // XXX save rei or not?

        free(headerCopy);
        return status;
    }
}
