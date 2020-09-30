#ifndef RETDEC_RETDEC_H
#define RETDEC_RETDEC_H

#include <iostream>
#include <iomanip>
#include <list>
#include <map>
#include <set>
#include <sstream>

#include <retdec/config/config.h>
#include <retdec/utils/filesystem.h>
#include <retdec/utils/time.h>

#include "function.h"
#include "ui.h"
#include "utils.h"

#ifndef WOPN_TAB
    #define WOPN_TAB                0x02
#endif

#ifndef WOPN_DP_RIGHT
    #define WOPN_DP_RIGHT           0x00040000
#endif

#ifndef PCF_MAKEPLACE_ALLOCATES
    #define PCF_MAKEPLACE_ALLOCATES 0x00000002
#endif

ssize_t idaapi retdec_ui_hook_callback(void *user_data, int notification_code, va_list va);

/**
 * Plugin's global data.
 */
class RetDec
{
public:
    RetDec();
    ~RetDec();

    bool idaapi run(size_t);
    static ssize_t idaapi on_event(RetDec *prd, int code, va_list va);

public:
    // Plugin information.
    //
    inline static const std::string pluginName         = "RetDec";
    inline static const std::string pluginID           = "avast.retdec - mod, build for IDA 7.2-7.4 by HTC";
    inline static const std::string pluginProducer     = "Avast Software";
    inline static const std::string pluginCopyright    = "Copyright 2020 " + pluginProducer;
    inline static const std::string pluginEmail        = "support@retdec.com";
    inline static const std::string pluginURL          = "https://retdec.com/";
    inline static const std::string pluginRetDecGithub = "https://github.com/avast/retdec";
    inline static const std::string pluginGithub       = "https://github.com/avast/retdec-idaplugin";
    inline static const std::string pluginContact      = pluginURL + "\nEMAIL: " + pluginEmail;
    inline static const std::string pluginVersion      = RELEASE_VERSION;
    inline static const std::string pluginHotkey       = "Alt-Shift-D";
    inline static const std::string pluginBuildDate    = retdec::utils::getCurrentDate();

    /// Plugin information showed in the About box.
    addon_info_t pluginInfo;
    int pluginRegNumber = -1;

public:
    // Decompilation.
    //
    static bool fullDecompilation();
    static Function* selectiveDecompilation(ea_t ea, bool redecompile, bool regressionTests = false);

    Function* selectiveDecompilationAndDisplay(ea_t ea, bool redecompile);
    void displayFunction(Function* f, ea_t ea);

    void modifyFunctions(Token::Kind k,
                         const std::string& oldVal,
                         const std::string& newVal);
    void modifyFunction(func_t* f,
                        Token::Kind k,
                        const std::string& oldVal,
                        const std::string& newVal);

    ea_t getFunctionEa(const std::string& name);
    func_t* getIdaFunction(const std::string& name);
    ea_t getGlobalVarEa(const std::string& name);

    /// Currently displayed function.
    Function* m_pFunction = nullptr;

    /// All the decompiled functions.
    static std::map<func_t*, Function> fnc2fnc;

    /// Decompilation config.
    static retdec::config::Config config;

public:
    // UI.
    //
    TWidget* custViewer = nullptr;
    TWidget* codeViewer = nullptr;

    fullDecompilation_ah_t fullDecompilation_ah = fullDecompilation_ah_t(*this);
    const action_desc_t fullDecompilation_ah_desc = ACTION_DESC_LITERAL(
            fullDecompilation_ah_t::actionName,
            fullDecompilation_ah_t::actionLabel,
            &fullDecompilation_ah,
            fullDecompilation_ah_t::actionHotkey,
            nullptr,
            -1);

    jump2asm_ah_t jump2asm_ah = jump2asm_ah_t(*this);
    const action_desc_t jump2asm_ah_desc = ACTION_DESC_LITERAL(
            jump2asm_ah_t::actionName,
            jump2asm_ah_t::actionLabel,
            &jump2asm_ah,
            jump2asm_ah_t::actionHotkey,
            nullptr,
            -1);

    copy2asm_ah_t copy2asm_ah = copy2asm_ah_t(*this);
    const action_desc_t copy2asm_ah_desc = ACTION_DESC_LITERAL(
            copy2asm_ah_t::actionName,
            copy2asm_ah_t::actionLabel,
            &copy2asm_ah,
            copy2asm_ah_t::actionHotkey,
            nullptr,
            -1);

    funcComment_ah_t funcComment_ah = funcComment_ah_t(*this);
    const action_desc_t funcComment_ah_desc = ACTION_DESC_LITERAL(
            funcComment_ah_t::actionName,
            funcComment_ah_t::actionLabel,
            &funcComment_ah,
            funcComment_ah_t::actionHotkey,
            nullptr,
            -1);

    renameGlobalObj_ah_t renameGlobalObj_ah = renameGlobalObj_ah_t(*this);
    const action_desc_t renameGlobalObj_ah_desc = ACTION_DESC_LITERAL(
            renameGlobalObj_ah_t::actionName,
            renameGlobalObj_ah_t::actionLabel,
            &renameGlobalObj_ah,
            renameGlobalObj_ah_t::actionHotkey,
            nullptr,
            -1);

    openXrefs_ah_t openXrefs_ah = openXrefs_ah_t(*this);
    const action_desc_t openXrefs_ah_desc = ACTION_DESC_LITERAL(
            openXrefs_ah_t::actionName,
            openXrefs_ah_t::actionLabel,
            &openXrefs_ah,
            openXrefs_ah_t::actionHotkey,
            nullptr,
            -1);

    openCalls_ah_t openCalls_ah = openCalls_ah_t(*this);
    const action_desc_t openCalls_ah_desc = ACTION_DESC_LITERAL(
            openCalls_ah_t::actionName,
            openCalls_ah_t::actionLabel,
            &openCalls_ah,
            openCalls_ah_t::actionHotkey,
            nullptr,
            -1);

    changeFuncType_ah_t changeFuncType_ah = changeFuncType_ah_t(*this);
    const action_desc_t changeFuncType_ah_desc = ACTION_DESC_LITERAL(
            changeFuncType_ah_t::actionName,
            changeFuncType_ah_t::actionLabel,
            &changeFuncType_ah,
            changeFuncType_ah_t::actionHotkey,
            nullptr,
            -1);
};

#endif
