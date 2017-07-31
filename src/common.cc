/**
 * \file
 * \brief     Common sudo microservice functionalities.
 * \author    Chris Smeele
 * \copyright Copyright (c) 2016, 2017, Utrecht University
 */
#include "common.hh"
#include <rcMisc.h>

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

    std::list<boost::any> anyifyMsParams(const std::vector<msParam_t*> &msParams) {

        std::list<boost::any> argList;

        for (auto p : msParams) {
            if (p && p->type && p->inOutStruct) {
                // p->type is NULL when we have an undefined variable
                // as an argument.  Since we never have output-only
                // parameters, we can require all parameters to be
                // defined.

                if (!strcmp(p->type, STR_MS_T)) {
                    argList.push_back(stringFromMsp(p));
                } else if (!strcmp(p->type, INT_MS_T)) {
                    argList.push_back(parseMspForPosInt(p));
                } else if (!strcmp(p->type, KeyValPair_MS_T)) {
                    // Add two dummy key value pairs to work around a
                    // 4.2.1 bug: https://github.com/irods/irods/issues/3617
                    // When a keyValPair_t contains only a single k/v
                    // pair, it is serialized as a string in the iRODS
                    // rule language engine plugin. There is currently
                    // no way to pass a kvp of size 1 to an iRODS rule
                    // from a microservice.
                    // This should be fixed in 4.2.2.
                    addKeyVal((keyValPair_t*)(p->inOutStruct), "__dummy1", "_");
                    addKeyVal((keyValPair_t*)(p->inOutStruct), "__dummy2", "_");
                    argList.push_back((keyValPair_t*)(p->inOutStruct));
                } else { // Add types when needed.
                    writeLog(__func__, LOG_ERROR, "Unsupported MSI parameter type <"s + p->type + ">");
                }
            } else {
                writeLog(__func__, LOG_ERROR, "NULL MSI parameter");
            }
        }

        return argList;
    }

    int callRule(const std::string &ruleName,
                 const std::vector<msParam_t*> &msParams,
                 ruleExecInfo_t *rei) {

        return callRule(ruleName, anyifyMsParams(msParams), rei);
    }

    int callRule(const std::string &ruleName, const std::list<boost::any> &params_, ruleExecInfo_t *rei) {

        // Copy params, because applyRuleWithInOutVars expects a mutable list.
        auto params = params_;

        return applyRuleWithInOutVars(ruleName.c_str(), params, rei);
    }
}
