#pragma once

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

// Windows Header Files:
#include <windows.h>
#include <functional>

// Shell Lightweight API Header File
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

#ifdef __NT__
#pragma warning(push)
#pragma warning(disable:4309 4244 4267)           // disable "truncation of constant value" warning from IDA SDK, conversion from 'ssize_t' to 'int', possible loss of data
#endif // __NT__

typedef unsigned long ulong;

// IDA SDK Header Files
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <entry.hpp>
#include <fpro.h>
#include <kernwin.hpp>
#include <hexrays.hpp>
#include <struct.hpp>
#include <typeinf.hpp>
#include <enum.hpp>
#include <diskio.hpp>
#include <auto.hpp>

#define DOT             0x2E
#define SPACE           0x20
#define ONE_MB          (1024 * 1024)

#define countof(x)      (sizeof(x) / sizeof((x)[0]))

#define DEF_REVERSE_SIZE    10
#define DEF_MIN_FUNC_LENGTH 6

#ifdef _DEBUG
#define _VERIFY(x)  _ASSERTE(x)

#define WIN32CHECK(x)   { \
        DWORD __dwErr__ = GetLastError(); \
        _ASSERTE(x); \
        SetLastError(__dwErr__); \
    };
#else
#define _VERIFY(x)  (x)
#define WIN32CHECK(x)   (x)
#endif

// Size of string sans terminator
#define SIZESTR(x) (sizeof(x) - 1)

// Data and function alignment
#define ALIGN(_x_) __declspec(align(_x_))

#define putDword(ea) create_dword(ea, sizeof(DWORD))
#ifndef __EA64__
#define putEa(ea) create_dword(ea, sizeof(ea_t))
#else
#define putEa(ea) create_qword(ea, sizeof(ea_t))
#endif

template<typename T>
struct print1_accepts_qstring
{
	template<typename U, void (U::*)(qstring *, const cfunc_t *) const> struct yay_sfinae {};
	template<typename U> static char test(yay_sfinae<U, &U::print1>*);
	template<typename U> static int test(...);
	static const bool value = sizeof(test<T>(0)) == sizeof(char);
};

// For IDA7.1 and newer
template <class T>
void print1wrapper(std::true_type, const T *e, qstring *qbuf, const cfunc_t *func) {
	e->print1(qbuf, func);
};

// For older SDKs
template <class T>
void print1wrapper(std::false_type, const T *e, qstring *qbuf, const cfunc_t *func) {
	char lbuf[MAXSTR];
	const size_t len = e->print1(lbuf, sizeof(lbuf) - 1, func);
	qstring temp(lbuf, len);
	qbuf->swap(temp);
};

template <class T>
void print1wrapper(const T *e, qstring *qbuf, const cfunc_t *func) {
	return print1wrapper(
		std::integral_constant<bool, print1_accepts_qstring<T>::value>(),
		e, qbuf, func);
}

// Get IDA 32 bit value with verification
template <class T> BOOL getVerify32_t(ea_t eaPtr, T &rValue)
{
	// Location valid?
	if (is_loaded(eaPtr))
	{
		// Get 32bit value
		rValue = (T)get_32bit(eaPtr);
		return(TRUE);
	}

	return(FALSE);
}

// Get address/pointer value
inline ea_t getEa(ea_t ea)
{
#ifndef __EA64__
	return((ea_t)get_32bit(ea));
#else
	return((ea_t)get_64bit(ea));
#endif
}


// Returns TRUE if ea_t sized value flags
inline BOOL isEa(flags_t f)
{
#ifndef __EA64__
	return(is_dword(f));
#else
	return(is_qword(f));
#endif
}

uint str2int(qstring& str);
void get_string(ea_t ea, qstring &strdst);
qstring get_expr_name(cexpr_t *e);
bool get_expr_name(citem_t *citem, qstring& rv);

std::string get_procname();

void setUnknown(ea_t ea, int size);
int addStrucMember(struc_t *sptr, char *name, ea_t offset, flags_t flag, opinfo_t *type, asize_t nbytes);

void logmsg(unsigned int level, const char *fmt, ...);
ea_t get_aword(ea_t addr);

enum DEBUG_LEVELS {
	OUTPUT, // output printed to output file
	ERROR_, // error printed to error file
	INFO, // print to IDA
	INTERACTIVE, // show on IDA interface
	DEBUG // print to IDA
};

#define CURRENT_DEBUG_LEVEL ERROR_
//////////////////////////////////////////////////////////////////////////