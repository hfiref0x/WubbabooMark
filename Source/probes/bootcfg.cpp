/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       BOOTCFG.CPP
*
*  VERSION:     1.00
*
*  DATE:        01 Jul 2023
*
*  Boot configuration probes.
*  Elevation required.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

#define	BcdLibraryBoolean_DebuggerEnabled            0x16000010
#define BcdLibraryBoolean_DisableIntegrityChecks     0x16000048
#define	BcdLibraryBoolean_AllowPrereleaseSignatures  0x16000049
#define BcdOSLoaderBoolean_WinPEMode                 0x26000022
#define	BcdOSLoaderBoolean_AllowPrereleaseSignatures 0x26000027
#define BcdOSLoaderBoolean_KernelDebuggerEnabled     0x260000a0

#define BCDPROBE_LIB_KDBG   0
#define BCDPROBE_LIB_NOIC   1
#define BCDPROBE_LIB_TEST   2
#define BCDPROBE_LDR_WINPE  3
#define BCDPROBE_LDR_TEST   4
#define BCDPROBE_LDR_KDBG   5

typedef struct _BCD_PROBE {
    ULONG ProbeValue;
    ULONG ProbeResult;
    LPWSTR Description;
} BCD_PROBE, * PBCD_PROBE;

BCD_PROBE bcdProbes[] = {
    { BcdLibraryBoolean_DebuggerEnabled, ERROR_NOT_FOUND, (LPWSTR)TEXT("KernelDebuggerEnabled") },
    { BcdLibraryBoolean_DisableIntegrityChecks, ERROR_NOT_FOUND, (LPWSTR)TEXT("DisableIntegrityChecks") },
    { BcdLibraryBoolean_AllowPrereleaseSignatures, ERROR_NOT_FOUND, (LPWSTR)TEXT("TestModeEnabled") },
    { BcdOSLoaderBoolean_WinPEMode, ERROR_NOT_FOUND, (LPWSTR)TEXT("WinPEMode") },
    { BcdOSLoaderBoolean_AllowPrereleaseSignatures, ERROR_NOT_FOUND, (LPWSTR)TEXT("TestModeEnabled") },
    { BcdOSLoaderBoolean_KernelDebuggerEnabled, ERROR_NOT_FOUND, (LPWSTR)TEXT("KernelDebuggerEnabled") },
};

#define GUID_CURRENT_BOOT_ENTRY TEXT("{FA926493-6F1C-4193-A414-58F0B2456D1E}")

/*
* BcdGetBoolFromArgName
*
* Purpose:
*
* Retrieve bool value from named argument.
*
*/
HRESULT BcdGetBoolFromArgName(
    _In_ LPWSTR Argument,
    _In_ IWbemClassObject* PropertyClass,
    _In_ PBOOL Result
)
{
    HRESULT	hr;
    VARIANT	var;
    CIMTYPE	vt_type;

    *Result = FALSE;

    VariantInit(&var);
    var.vt = VT_BOOL;

    hr = PropertyClass->Get(Argument, 0, &var, &vt_type, 0);
    if (hr == WBEM_S_NO_ERROR &&
        vt_type == VT_BOOL)
    {
        *Result = var.boolVal;
    }

    VariantClear(&var);

    return hr;
}

/*
* BcdSetDWORDArgument
*
* Purpose:
*
* Put DWORD value into call parameters.
*
*/
BOOL BcdSetDWORDArgument(
    _In_ IWbemClassObject* PropertyClass,
    _In_ LPWSTR Argument,
    _In_ DWORD Value
)
{
    VARIANT var;
    HRESULT hr;

    VariantInit(&var);
    var.vt = VT_I4;
    var.lVal = Value;

    hr = PropertyClass->Put(Argument, 0, &var, 0);
    VariantClear(&var);

    return hr == WBEM_S_NO_ERROR;
}

/*
* BcdSetStringArgument
*
* Purpose:
*
* Put BSTR string into call parameters.
*
*/
BOOL BcdSetStringArgument(
    _In_ IWbemClassObject* PropertyClass,
    _In_ LPWSTR Argument,
    _In_ LPWSTR String
)
{
    VARIANT var;
    HRESULT hr;

    VariantInit(&var);
    var.vt = VT_BSTR;
    var.bstrVal = SysAllocString(String);
    if (var.bstrVal == NULL)
        return FALSE;

    hr = PropertyClass->Put(Argument, 0, &var, 0);

    SysFreeString(var.bstrVal);
    VariantClear(&var);
    return hr == WBEM_S_NO_ERROR;
}

/*
* BcdGetMethodResult
*
* Purpose:
*
* Extract method result as bool value.
*
*/
HRESULT BcdGetMethodResult(
    _In_ IWbemClassObject* pOutParamsObj,
    _Inout_ PBOOL Result)
{
    HRESULT hr;

    hr = BcdGetBoolFromArgName((LPWSTR)TEXT("ReturnValue"),
        pOutParamsObj, Result);

    if (SUCCEEDED(hr)) {

        if (*Result == FALSE)
            hr = E_FAIL;
    }

    return hr;
}

/*
* BcdGetObjectFromArgs
*
* Purpose:
*
* Extract method object from arguments.
*
*/
HRESULT BcdGetObjectFromArgs(
    _In_ IWbemClassObject* PropertyClass,
    _In_ LPWSTR Argument,
    _Inout_ IWbemClassObject** Result
)
{
    HRESULT	hr;
    VARIANT	var;
    CIMTYPE	vt_type;

    *Result = FALSE;

    VariantInit(&var);
    var.vt = VT_UNKNOWN;

    hr = PropertyClass->Get(Argument, 0, &var, &vt_type, 0);
    if (hr == WBEM_S_NO_ERROR &&
        vt_type == VT_UNKNOWN)
    {
        hr = var.punkVal->QueryInterface(IID_IWbemClassObject, (void**)Result);
    }

    VariantClear(&var);
    return hr;
}

/*
* BcdMethodCall
*
* Purpose:
*
* Execute object method.
*
*/
HRESULT BcdMethodCall(
    _In_ IWbemServices* WbemServices,
    _In_ IWbemClassObject* ObjectInstance,
    _In_ IWbemClassObject* pInParamsObj,
    _In_ IWbemClassObject** pOutParamsObj,
    _In_ BSTR MethodName
)
{
    BOOL bResult = FALSE;
    HRESULT hr;
    VARIANT var;

    VariantInit(&var);

    hr = ObjectInstance->Get(TEXT("__Relpath"), 0, &var, NULL, NULL);
    if (FAILED(hr))
        return hr;

    hr = WbemServices->ExecMethod(var.bstrVal,
        MethodName,
        0,
        NULL,
        pInParamsObj,
        pOutParamsObj,
        NULL);

    if (FAILED(hr))
        return hr;

    if (*pOutParamsObj == NULL)
        return E_OUTOFMEMORY;

    hr = BcdGetMethodResult(*pOutParamsObj, &bResult);
    if (SUCCEEDED(hr)) {
        if (bResult == FALSE)
            hr = E_FAIL;
    }

    return hr;
}

/*
* BcdInitMethodCall
*
* Purpose:
*
* Get COM class object and it method by name.
*
*/
HRESULT BcdInitMethodCall(
    _In_ IWbemServices* WbemServices,
    _In_ LPWSTR ObjectClassName,
    _In_ LPWSTR MethodName,
    _Out_ IWbemClassObject** InParamsObj,
    _Out_ IWbemClassObject** ObjectClass,
    _Out_ BSTR* AllocatedMethodName
)
{
    BOOL bOk = FALSE;
    HRESULT hr = E_FAIL;
    IWbemClassObject* pObjectClass = NULL;
    IWbemClassObject* pInParamsClass = NULL;
    IWbemClassObject* pInParamsObj = NULL;
    BSTR objectClass = NULL, methodName = NULL;

    *InParamsObj = NULL;
    *ObjectClass = NULL;
    *AllocatedMethodName = NULL;

    do {

        objectClass = SysAllocString(ObjectClassName);
        if (objectClass == NULL)
            break;

        methodName = SysAllocString(MethodName);
        if (methodName == NULL)
            break;

        hr = WbemServices->GetObject(objectClass,
            WBEM_FLAG_RETURN_WBEM_COMPLETE,
            NULL,
            &pObjectClass,
            NULL);

        if (hr != WBEM_S_NO_ERROR)
            break;

        hr = pObjectClass->GetMethod(methodName, 0, &pInParamsClass, NULL);
        if (hr != WBEM_S_NO_ERROR)
            break;

        hr = pInParamsClass->SpawnInstance(0, &pInParamsObj);
        if (hr != WBEM_S_NO_ERROR)
            break;

        *InParamsObj = pInParamsObj;
        *ObjectClass = pObjectClass;
        *AllocatedMethodName = methodName;

        bOk = TRUE;

    } while (FALSE);

    if (pInParamsClass) pInParamsClass->Release();

    if (objectClass) SysFreeString(objectClass);

    if (bOk == FALSE && methodName)
        SysFreeString(methodName);

    return hr;
}

/*
* BcdOpenDefaultOsLoader
*
* Purpose:
*
* Retrieve default OsLoader object to work with.
*
*/
HRESULT BcdOpenDefaultOsLoader(
    _In_ IWbemServices* WbemServices,
    _In_ IWbemClassObject* pBCDStoreObject,
    _Out_ IWbemClassObject** OsLoaderObject)
{
    HRESULT hr;
    IWbemClassObject* pOsLoaderObject = NULL;
    IWbemClassObject* pObjectClass = NULL;
    IWbemClassObject* pInParamsObj = NULL;
    IWbemClassObject* pOutParamsObj = NULL;
    BSTR methodName = NULL;

    *OsLoaderObject = NULL;

    hr = BcdInitMethodCall(WbemServices,
        (LPWSTR)TEXT("BcdStore"),
        (LPWSTR)TEXT("OpenObject"),
        &pInParamsObj,
        &pObjectClass,
        &methodName);

    if (FAILED(hr))
        return hr;

    if (BcdSetStringArgument(pInParamsObj,
        (LPWSTR)TEXT("Id"),
        (LPWSTR)GUID_CURRENT_BOOT_ENTRY)) //{current} 
    {
        hr = BcdMethodCall(WbemServices,
            pBCDStoreObject,
            pInParamsObj,
            &pOutParamsObj,
            methodName);

        if (SUCCEEDED(hr) && pOutParamsObj) {
            hr = BcdGetObjectFromArgs(pOutParamsObj,
                (LPWSTR)TEXT("Object"), &pOsLoaderObject);

            if (SUCCEEDED(hr))
                *OsLoaderObject = pOsLoaderObject;
        }

    }

    if (methodName) SysFreeString(methodName);
    if (pOutParamsObj) pOutParamsObj->Release();
    if (pInParamsObj) pInParamsObj->Release();
    if (pObjectClass) pObjectClass->Release();

    return hr;
}

/*
* BcdOpenDefaultStore
*
* Purpose:
*
* Retrieve object to work with default BCD store.
*
*/
HRESULT BcdOpenDefaultStore(
    _In_ IWbemServices* WbemServices,
    _Out_ IWbemClassObject** BCDStoreObject)
{
    HRESULT hr;
    IWbemClassObject* pStoreObject = NULL;
    IWbemClassObject* pObjectClass = NULL;
    IWbemClassObject* pInParamsObj = NULL;
    IWbemClassObject* pOutParamsObj = NULL;
    BSTR methodName = NULL;

    *BCDStoreObject = NULL;

    hr = BcdInitMethodCall(WbemServices,
        (LPWSTR)TEXT("BcdStore"),
        (LPWSTR)TEXT("OpenStore"),
        &pInParamsObj,
        &pObjectClass,
        &methodName);

    if (FAILED(hr))
        return hr;

    if (pObjectClass == NULL)
        return E_FAIL;

    if (BcdSetStringArgument(pInParamsObj,
        (LPWSTR)TEXT("File"),
        (LPWSTR)TEXT("")))
    {
        hr = BcdMethodCall(WbemServices,
            pObjectClass,
            pInParamsObj,
            &pOutParamsObj,
            methodName);

        if (SUCCEEDED(hr) && pOutParamsObj) {
            hr = BcdGetObjectFromArgs(pOutParamsObj,
                (LPWSTR)TEXT("Store"), &pStoreObject);

            if (SUCCEEDED(hr))
                *BCDStoreObject = pStoreObject;
        }

    }

    if (methodName) SysFreeString(methodName);
    if (pOutParamsObj) pOutParamsObj->Release();
    if (pInParamsObj) pInParamsObj->Release();
    pObjectClass->Release();

    return hr;
}

/*
* BcdGetElementAsBool
*
* Purpose:
*
* Retrieve bool value from BCD store.
*
*/
BOOL BcdGetElementAsBool(
    _In_ IWbemServices* WbemServices,
    _In_ IWbemClassObject* OSLoaderObject,
    _In_ DWORD ElementID,
    _In_ PULONG Value)
{
    HRESULT hr;
    IWbemClassObject* pElementObject = NULL;
    IWbemClassObject* pObjectClass = NULL;
    IWbemClassObject* pInParamsObj = NULL;
    IWbemClassObject* pOutParamsObj = NULL;
    BSTR methodName;
    ULONG value = 0;

    *Value = 0;

    hr = BcdInitMethodCall(WbemServices,
        (LPWSTR)TEXT("BcdObject"),
        (LPWSTR)TEXT("GetElement"),
        &pInParamsObj,
        &pObjectClass,
        &methodName);

    if (SUCCEEDED(hr)) {

        if (BcdSetDWORDArgument(pInParamsObj,
            (LPWSTR)TEXT("Type"),
            ElementID))
        {
            hr = BcdMethodCall(WbemServices,
                OSLoaderObject,
                pInParamsObj,
                &pOutParamsObj,
                methodName);

            if (SUCCEEDED(hr) && pOutParamsObj) {

                hr = BcdGetObjectFromArgs(pOutParamsObj,
                    (LPWSTR)TEXT("Element"), &pElementObject);

                if (SUCCEEDED(hr)) {

                    hr = BcdGetBoolFromArgName(
                        (LPWSTR)TEXT("Boolean"),
                        pElementObject, (PBOOL)&value);

                    if (SUCCEEDED(hr)) {
                        *Value = value;
                    }

                    pElementObject->Release();
                }
            }
            else {
                if (hr == HRESULT_FROM_NT(STATUS_NOT_FOUND))
                    RtlSetLastWin32Error(ERROR_NOT_FOUND);
            }
        }
    }

    if (methodName) SysFreeString(methodName);
    if (pOutParamsObj) pOutParamsObj->Release();
    if (pInParamsObj) pInParamsObj->Release();
    if (pObjectClass) pObjectClass->Release();

    return SUCCEEDED(hr);
}

/*
* SkiBcdValidate
*
* Purpose:
*
* Compare results.
*
*/
VOID SkiBcdValidate(
    _In_ IWbemServices* WbemServices,
    _In_ IWbemClassObject* OsLoaderObject
)
{
    NTSTATUS ntStatus;
    ULONG probeResult = 0;
    ULONG returnLength;
    SYSTEM_CODEINTEGRITY_INFORMATION sci;
    SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX skdi;

    BOOL ReportedTestMode = FALSE;
    BOOL ReportedCiEnabled = FALSE;

    sci.Length = sizeof(sci);

    ntStatus = NtQuerySystemInformation(SystemCodeIntegrityInformation,
        &sci,
        sizeof(sci),
        &returnLength);

    if (NT_SUCCESS(ntStatus)) {
        ReportedTestMode = sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN;
        ReportedCiEnabled = sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED;
    }
    else {

        SkReportNtCallRIP(ntStatus,
            (LPWSTR)TEXT("Failed to query CI information"),
            (LPWSTR)TEXT("NtQuerySystemInformation"),
            (LPWSTR)TEXT("SystemCodeIntegrityInformation"));

    }

    for (ULONG i = 0; i < RTL_NUMBER_OF(bcdProbes); i++) {

        if (BcdGetElementAsBool(WbemServices,
            OsLoaderObject,
            bcdProbes[i].ProbeValue,
            &probeResult))
        {
            bcdProbes[i].ProbeResult = probeResult;
        }
    }

    //
    // TEST MODE? SURE NOT.
    //
    if (ReportedTestMode == FALSE) {

        if (bcdProbes[BCDPROBE_LDR_TEST].ProbeResult > 0 &&
            bcdProbes[BCDPROBE_LDR_TEST].ProbeResult != ERROR_NOT_FOUND)
        {
            SkReportBcdProbeMismatch(ReportedTestMode, 
                bcdProbes[BCDPROBE_LDR_TEST].Description, 
                bcdProbes[BCDPROBE_LDR_TEST].ProbeValue);
        }

        if (bcdProbes[BCDPROBE_LIB_TEST].ProbeResult > 0 &&
            bcdProbes[BCDPROBE_LIB_TEST].ProbeResult != ERROR_NOT_FOUND)
        {
            SkReportBcdProbeMismatch(ReportedTestMode, 
                bcdProbes[BCDPROBE_LIB_TEST].Description, 
                bcdProbes[BCDPROBE_LIB_TEST].ProbeValue);
        }
    }

    //
    // CODEINTEGRITY? ALWAYS ENABLED.
    //
    if (ReportedCiEnabled) {
        if (bcdProbes[BCDPROBE_LDR_WINPE].ProbeResult > 0 &&
            bcdProbes[BCDPROBE_LDR_WINPE].ProbeResult != ERROR_NOT_FOUND)
        {
            SkReportBcdProbeMismatch(ReportedCiEnabled, 
                bcdProbes[BCDPROBE_LDR_WINPE].Description,
                bcdProbes[BCDPROBE_LDR_WINPE].ProbeValue);
        }

        if (bcdProbes[BCDPROBE_LIB_NOIC].ProbeResult > 0 &&
            bcdProbes[BCDPROBE_LIB_NOIC].ProbeResult != ERROR_NOT_FOUND)
        {
            SkReportBcdProbeMismatch(ReportedCiEnabled, 
                bcdProbes[BCDPROBE_LIB_NOIC].Description,
                bcdProbes[BCDPROBE_LIB_NOIC].ProbeValue);
        }
    }

    //
    // KERNEL DEBUG? OF COURSE NOT.
    //
    ntStatus = NtQuerySystemInformation(
        SystemKernelDebuggerInformationEx,
        &skdi,
        sizeof(skdi),
        &returnLength);

    if (NT_SUCCESS(ntStatus))
    {
        if (skdi.DebuggerEnabled == FALSE) {
            if (bcdProbes[BCDPROBE_LDR_KDBG].ProbeResult > 0 &&
                bcdProbes[BCDPROBE_LDR_KDBG].ProbeResult != ERROR_NOT_FOUND)
            {
                SkReportBcdProbeMismatch(skdi.DebuggerEnabled, 
                    bcdProbes[BCDPROBE_LDR_KDBG].Description,
                    bcdProbes[BCDPROBE_LDR_KDBG].ProbeValue);
            }

            if (bcdProbes[BCDPROBE_LIB_KDBG].ProbeResult > 0 &&
                bcdProbes[BCDPROBE_LIB_KDBG].ProbeResult != ERROR_NOT_FOUND)
            {
                SkReportBcdProbeMismatch(skdi.DebuggerEnabled, 
                    bcdProbes[BCDPROBE_LIB_KDBG].Description,
                    bcdProbes[BCDPROBE_LIB_KDBG].ProbeValue);
            }
        }
    }
    else {
        SkReportNtCallRIP(ntStatus,
            (LPWSTR)TEXT("Failed to query kernel debugger information"),
            (LPWSTR)TEXT("NtQuerySystemInformation"),
            (LPWSTR)TEXT("SystemKernelDebuggerInformationEx"));
    }
}

/*
* SkTestBootConfiguration
*
* Purpose:
*
* Read specific values from Boot Configuration Data current entry and validate them against API.
*
*/
BOOL SkTestBootConfiguration()
{
    ULONG oldAnomalyCount = SkiGetAnomalyCount();
    HRESULT hr = S_OK;
    IWbemClassObject* pStoreObject = NULL;
    IWbemClassObject* pOsLoaderObject = NULL;
    IWbemLocator* WbemLocator = NULL;
    IWbemServices* WbemServices = NULL;
    BSTR bstrServer = NULL;

    bstrServer = SysAllocString(L"ROOT\\WMI");
    if (bstrServer == NULL) {

        SkReportComCallRIP(E_NOT_SUFFICIENT_BUFFER,
            (LPWSTR)TEXT("Failed to allocate memory for WMI root"),
            (LPWSTR)TEXT("SysAllocString"),
            NULL);

        return FALSE;
    }

    hr = CoCreateInstance(CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)&WbemLocator);

    if (SUCCEEDED(hr)) {

        hr = WbemLocator->ConnectServer(bstrServer, NULL, NULL, NULL, 0, NULL, NULL, &WbemServices);
        if (SUCCEEDED(hr)) {

            hr = CoSetProxyBlanket(WbemServices,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                NULL,
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                NULL,
                EOAC_NONE);

            if (SUCCEEDED(hr)) {

                hr = BcdOpenDefaultStore(WbemServices, &pStoreObject);
                if (SUCCEEDED(hr)) {

                    hr = BcdOpenDefaultOsLoader(WbemServices, pStoreObject, &pOsLoaderObject);
                    if (SUCCEEDED(hr)) {

                        SkiBcdValidate(WbemServices, pOsLoaderObject);
                        pOsLoaderObject->Release();

                    }
                    else {
                        SkReportComCallRIP(hr,
                            (LPWSTR)TEXT("Failed to open default OsLoader store"),
                            (LPWSTR)TEXT("BcdOpenDefaultOsLoader"),
                            NULL);
                    }

                    pStoreObject->Release();
                }
                else {

                    SkReportComCallRIP(hr,
                        (LPWSTR)TEXT("Failed to open default BCD store"),
                        (LPWSTR)TEXT("BcdOpenBCDStoreDefault"),
                        NULL);

                }

            }
            else {

                SkReportComCallRIP(hr,
                    (LPWSTR)TEXT("Failed to set authentification for proxy calls"),
                    (LPWSTR)TEXT("CoSetProxyBlanket"),
                    NULL);

            }

            WbemServices->Release();
        }
        else {

            SkReportComCallRIP(hr,
                (LPWSTR)TEXT("Failed to connect WMI server"),
                (LPWSTR)TEXT("ConnectServer"),
                NULL);

        }

        WbemLocator->Release();
    }
    else {

        SkReportComCallRIP(hr,
            (LPWSTR)TEXT("Failed to create WMI object"),
            (LPWSTR)TEXT("CoCreateInstance"),
            NULL);

    }

    SysFreeString(bstrServer);
    return (SkiGetAnomalyCount() == oldAnomalyCount);
}
