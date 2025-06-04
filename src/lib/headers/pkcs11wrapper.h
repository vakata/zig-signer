#ifdef _WIN32
#pragma pack(push, cryptoki, 1)
#define CK_IMPORT_SPEC __declspec(dllimport)
#ifdef CRYPTOKI_EXPORTS
#define CK_EXPORT_SPEC __declspec(dllexport)
#else
#define CK_EXPORT_SPEC CK_IMPORT_SPEC
#endif
#define CK_CALL_SPEC __cdecl
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) \
    returnType CK_EXPORT_SPEC CK_CALL_SPEC name
#define CK_DECLARE_FUNCTION(returnType, name) \
    returnType CK_EXPORT_SPEC CK_CALL_SPEC name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType (CK_CALL_SPEC CK_PTR name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#else
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) \
    returnType name
#define CK_DECLARE_FUNCTION(returnType, name) \
    returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType (* name)
#ifndef NULL_PTR
    #define NULL_PTR 0
#endif
#endif

#include "pkcs11.h"

