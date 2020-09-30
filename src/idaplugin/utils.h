
#ifndef RETDEC_UTILS_H
#define RETDEC_UTILS_H

#include <windows.h>
#include <string>
#include <sstream>

#pragma comment(lib, "kernel32.lib")

// IDA SDK includes.
//
#include <ida.hpp> // this must be included before other idasdk headers
#include <auto.hpp>
#include <bytes.hpp>
#include <demangle.hpp>
#include <diskio.hpp>
#include <frame.hpp>
#include <funcs.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <moves.hpp>
#include <segment.hpp>
#include <strlist.hpp>
#include <struct.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>

enum ida_version_t
{
    ver_error = 0,
    ida_old,
    ida_71, // IDA 7.1 and below
    ida_72,
    ida_73,
    ida_74,
    ida_75, // IDA 7.5 and above
    ida_future,
};

// General print msg macros.
//
#define PRINT_DEBUG   true  // false to turn off VERIFY, FUNC_ENTER, FUNC_LEAVE, DBG_MSG
#define PRINT_ERROR   true
#define PRINT_WARNING true
#define PRINT_INFO    true

#define VERIFY(x) if (!(x)) { DBG_MSG(__FUNCTION__ " - Verify failed (" #x ")\n"); }

#define FUNC_ENTER(...) DBG_MSG(__FUNCTION__ " " __VA_ARGS__ " enter.\n");
#define FUNC_LEAVE(...) DBG_MSG(__FUNCTION__ " " __VA_ARGS__ " leave.\n");

// HTC - do not call IDA msg function in the callback function
#define DBG_MSG(body)                                                          \
    if (PRINT_DEBUG)                                                           \
    {                                                                          \
        std::stringstream ss;                                                  \
        ss << std::showbase << "[RetDec debug] " << body;                      \
        OutputDebugStringA(ss.str().c_str());                                  \
    }

/// Use this only for non-critical error messages.
#define ERROR_MSG(body)                                                        \
    if (PRINT_ERROR)                                                           \
    {                                                                          \
        std::stringstream ss;                                                  \
        ss << std::showbase << "[RetDec error] " << body;                      \
        msg("%s", ss.str().c_str());                                           \
    }

/// Use this only for user info warnings.
#define WARNING_MSG(body)                                                      \
    if (PRINT_WARNING)                                                         \
    {                                                                          \
        std::stringstream ss;                                                  \
        ss << std::showbase << "[RetDec warning] " << body;                    \
        msg("%s", ss.str().c_str());                                           \
    }

/// Use this to inform user.
#define INFO_MSG(body)                                                         \
    if (PRINT_INFO)                                                            \
    {                                                                          \
        std::stringstream ss;                                                  \
        ss << std::showbase << "[RetDec info] " << body;                       \
        msg("%s", ss.str().c_str());                                           \
    }

/// Use instead of IDA SDK's warning() function.
#define WARNING_GUI(body)                                                      \
    {                                                                          \
        std::stringstream ss;                                                  \
        ss << std::showbase << body;                                           \
        warning("%s", ss.str().c_str());                                       \
    }

/**
 * Is the file currently loaded to IDA relocable?
 */
bool isRelocatable();

/**
 * Is the file currently loaded to IDA some x86 flavour?
 */
bool isX86();

/**
 * Get full path to the file currently loaded to IDA.
 * Returns empty string if it is unable to get the file.
 * May ask user to specify the file in a GUI dialog.
 */
std::string getInputPath();

/**
 * Save IDA DB before decompilation to protect it if something goes wrong.
 * @param inSitu If true, DB is saved with the default IDA name.
 * @param suffix If @p inSitu is false, use this suffix to distinguish DBs.
 */
void saveIdaDatabase(bool inSitu = false, const std::string &suffix = ".dec-backup");

/**
 * Get IDA version
 */
ida_version_t getIDAVersion();

/**
 *  Get plugin path
 */
std::string getPluginPath();

#endif
