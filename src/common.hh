/**
 * \file
 * \brief     Group add sudo microservice.
 * \author    Chris Smeele
 * \copyright Copyright (c) 2016, Utrecht University. All rights reserved.
 */
#pragma once

#include "irods_includes.hh"
#include <vector>
#include <string>
#include <ostream>
#include <functional>
#include <tuple>

namespace Sudo {

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
     * \param rei The rule execution info struct.
     * \param f   The function to execute with altered privileges.
     *
     * \return    The return value of the provided function.
     */
    int sudo(ruleExecInfo_t *rei, std::function<int()> f);

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

    typedef std::pair<std::string, msParam_t*> ParamParam;
    typedef std::pair<std::string, std::string>  StrParam;
    typedef std::pair<std::string, int>          IntParam;

    class ParamArray {
        std::vector<std::string> labels;
        std::vector<void*> toFree;

    public:
        msParamArray_t array;
        const std::vector<std::string> &getLabels() {
            return labels;
        }

        ParamArray &operator<<(const ParamParam  &param);
        ParamArray &operator<<(const StrParam    &param);
        ParamArray &operator<<(const IntParam    &param);
        ParamArray &operator<<(const std::string &param);

        std::string getType(const std::string &label);
        std::string getStr( const std::string &label);
        int         getInt( const std::string &label);

        ParamArray()
            : array{ }
            { }

        ~ParamArray() {
            clearMsParamArray(&array, false);
            for (void *s : toFree)
                free(s);
        }

        friend int callRule(const std::string&, ParamArray&, ruleExecInfo_t*);
    };

    // MSI signature shorthands for use with policify().
    // Due to template characteristics, we need to have the rei
    // parameter up front. 
    typedef std::function<int(ruleExecInfo_t*,
                              msParam_t*)> msi_1param_t;
    typedef std::function<int(ruleExecInfo_t*,
                              msParam_t*, msParam_t*)> msi_2param_t;
    typedef std::function<int(ruleExecInfo_t*,
                              msParam_t*, msParam_t*, msParam_t*)> msi_3param_t;
    typedef std::function<int(ruleExecInfo_t*,
                              msParam_t*, msParam_t*, msParam_t*, msParam_t*)> msi_4param_t;
    typedef std::function<int(ruleExecInfo_t*,
                              msParam_t*, msParam_t*, msParam_t*, msParam_t*,
                              msParam_t*)> msi_5param_t;
    typedef std::function<int(ruleExecInfo_t*,
                              msParam_t*, msParam_t*, msParam_t*, msParam_t*,
                              msParam_t*, msParam_t*)> msi_6param_t;
    typedef std::function<int(ruleExecInfo_t*,
                              msParam_t*, msParam_t*, msParam_t*, msParam_t*,
                              msParam_t*, msParam_t*, msParam_t*)> msi_7param_t;
    typedef std::function<int(ruleExecInfo_t*,
                              msParam_t*, msParam_t*, msParam_t*, msParam_t*,
                              msParam_t*, msParam_t*, msParam_t*, msParam_t*)> msi_8param_t;

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
     * The `msParam_t` parameters should not be modified by the `pre`
     * and `post` actions. Any changes will not be visible to the
     * microservice.
     * 
     * \tparam Arg... Any number of `msParam_t` types.
     * 
     * \param name    The name that's used to generate policy names (i.e. `"acPre" + name + "()"`)
     * \param f       The msi implementation. Parameter order must be `rei*` first, then `msParam*`s.
     * \param rei     The rule execution information.
     * \param args... The `Arg...` amount of `msParam_t` parameters to be passed to the MSI.
     *
     * \return 0 if both policies and the actual msi succeeded,
     *         otherwise the first error code encountered.
     */
    template<class ...Arg>
    int policify(const std::string &name,
                 std::function<int(ruleExecInfo_t*, Arg...)> f,
                 ruleExecInfo_t *rei,
                 Arg... args) {

        ParamArray params;
        size_t i = 0;
        for (auto &param : {args...})
            params << ParamParam(std::string("*___param") + std::to_string(++i), param);
        
        int status = callRule(std::string("acPre") + name, params, rei);
        if (status) 
            return status;

        status = f(rei, args...);
        if (status) 
            return status;

        status = callRule(std::string("acPost") + name, params, rei);
        return status;
    }
}
