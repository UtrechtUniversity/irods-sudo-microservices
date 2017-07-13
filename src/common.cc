/**
 * \file
 * \brief     Common sudo microservice functionalities.
 * \author    Chris Smeele
 * \copyright Copyright (c) 2016, 2017, Utrecht University. All rights reserved.
 */
#include "common.hh"

namespace Sudo {

    void writeLog(const std::string &funcName, int type, const std::string &msg) {
        rodsLog(type, ("Sudo MSI "s + funcName + ": " + msg).c_str());
    }

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

    std::string stringFromMsp(msParam_t *param) {
        if (!param)
            return "null";

        const char *str = parseMspForStr(param);

        return str ? str : "null";
    }

    std::vector<std::string> stringifyMsParams(const std::vector<msParam_t*> &msParams) {

        std::vector<std::string> strParams;

        for (auto p : msParams) {
            if (!strcmp(p->type, STR_MS_T)) {
                strParams.push_back(stringFromMsp(p));
            } else if (!strcmp(p->type, INT_MS_T)) {
                strParams.push_back(std::to_string(parseMspForPosInt(p)));
            } else { // Add types when needed.
                writeLog(__func__, LOG_ERROR, "Unsupported MSI parameter type <"s + p->type + ">");
                strParams.push_back("");
            }
        }
        return strParams;
    }

    int callRule(const std::string &ruleName,
                 const std::vector<const char*> &params_,
                 ruleExecInfo_t *rei) {

        // Copy params, because applyRuleArg expects a mutable list.
        auto params = params_;

        // Call the rule.
        int status = applyRuleArg(ruleName.c_str(),
                                  params.data(),
                                  static_cast<int>(params.size()),
                                  rei,
                                  NO_SAVE_REI);
        return status;
    }

    int callRule(const std::string &ruleName,
                 const std::vector<std::string> &strParams,
                 ruleExecInfo_t *rei) {

        // Convert a list of std::string to a list of const char*.
        std::vector<const char*> params;
        for (const auto &v : strParams)
            params.push_back(v.c_str());

        return callRule(ruleName, params, rei);
    }

    int callRule(const std::string &ruleName,
                 const std::vector<msParam_t*> &msParams,
                 ruleExecInfo_t *rei) {

        // Convert a list of msParam_t to a list of stringified parameters.
        return callRule(ruleName, stringifyMsParams(msParams), rei);
    }
}
