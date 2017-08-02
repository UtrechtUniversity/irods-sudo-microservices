/**
 * \file
 * \brief     Common sudo microservice functionalities.
 * \author    Chris Smeele
 * \copyright Copyright (c) 2016, 2017, Utrecht University
 */
#pragma once

#include "irods_includes.hh"
#include <vector>
#include <string>
#include <functional>
#include <tuple>

namespace Sudo {
    using namespace std::literals::string_literals;

    void writeLog(const std::string &funcName, int type, const std::string &msg);

    std::tuple<std::string, std::string> splitUserZone(const std::string &userZoneStr,
                                                       const ruleExecInfo_t *rei);

    /**
     * \brief Call a function with elevated privileges.
     *
     * By temporarily modifying `authFlag` fields within the provided
     * `rei` structure, the given function will be allowed by iRODS to
     * perform administrative operations.
     *
     * Use this function with care, try to limit the amount of code
     * that executes within the function.
     *
     * \param rei  The rule execution info struct.
     * \param func The function to execute with altered privileges.
     *
     * \return     The return value of the provided function.
     */
    template<typename F>
    int sudo(ruleExecInfo_t *rei, F func) {
        // Backup.
        int authBupC = rei->uoic->authInfo.authFlag;
        int authBupP = rei->uoip->authInfo.authFlag;

        // Elevate privileges.
        rei->uoic->authInfo.authFlag = LOCAL_PRIV_USER_AUTH;
        rei->uoip->authInfo.authFlag = LOCAL_PRIV_USER_AUTH;

        int ret = -1;

        try {
            // Call privileged function.
            ret = func();
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

    /**
     * \brief Get a string from the given msParam.
     *
     * parseMspForStr returns NULL for strings that equal "null".
     * This is undesirable when we pass on "null" to e.g. ACL
     * functions, or use it as a metadata value.
     *
     * This function calls parseMspForStr and changes NULL return
     * values to "null". The caller is expected to check that this is
     * a valid string parameter (i.e. `param != NULL` and
     * `strcmp(param->type, STR_MS_T) == 0`).
     *
     * \param param
     *
     * \return
     */
    std::string stringFromMsp(msParam_t *param);

    /**
     * \brief Convert a list of msParams (of STR, INT or KeyVal types)
     *        to boost::any-wrapped types that are serializable by iRODS.
     *
     * Unconvertible types and undefined parameters are logged as
     * errors and discarded from the output.
     *
     * \param msParams
     *
     * \return
     */
    std::list<boost::any> anyifyMsParams(const std::vector<msParam_t*> &msParams);

    /**
     * \brief Call a rule with the given boost::any parameters.
     *
     * Output parameters are not supported.
     *
     * \param ruleName
     * \param msParams
     * \param rei
     *
     * \return The rule status code
     */
    int callRule(const std::string &ruleName,
                 const std::list<boost::any> &msParams,
                 ruleExecInfo_t *rei);

    /**
     * \brief Apply pre- and post actions around an MSI call.
     *
     * The execution order is: `pre`, `msi`, `post`. If any of these
     * steps fail, any remaining steps are not executed. Thus the
     * `pre` action can be used to prevent MSI execution.
     *
     * The `pre` and `post` actions are called with the same
     * parameters as the MSI itself.
     *
     * If any of the input parameters are not defined or of an
     * unrecognized type (only int, string and keyval list are
     * supported), a SYS_INVALID_INPUT_PARAM error is returned.
     *
     * The `msParam_t` parameters should not be modified by the `pre`
     * and `post` actions. Any changes will not be visible to the
     * microservice.
     *
     * \tparam Arg... Any number of `msParam_t` types.
     *
     * \param name    The name that's used to generate policy names (i.e. `"acPre" + name + "()"`)
     * \param f       The msi implementation callable. Parameter order must be `rei*` first, then `msParam*`s.
     * \param rei     The rule execution information.
     * \param args... The `Arg...` amount of `msParam_t` parameters to be passed to the MSI.
     *
     * \return 0 if both policies and the actual msi succeeded,
     *         otherwise the first error code encountered.
     */
    template<typename F, typename... Arg>
    int policify(const std::string &name,
                 F func,
                 ruleExecInfo_t *rei,
                 Arg... args) {

        auto argList = anyifyMsParams({args...});
        if (argList.size() != sizeof...(args)) {
            // Could not parse all arguments (unrecognized types or undefined arguments).
            return SYS_INVALID_INPUT_PARAM;
        }

        int status = callRule("acPre"s + name, argList, rei);
        if (status)
            return status;

        status = func(rei, args...);
        if (status)
            return status;

        status = callRule("acPost"s + name, argList, rei);
        return status;
    }
}
