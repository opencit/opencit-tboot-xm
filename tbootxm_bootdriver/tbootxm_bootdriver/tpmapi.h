#pragma once

#ifndef TPMAPI_H
#define TPMAPI_H

#include <ntifs.h>
#include <ntddk.h>
#include <winerror.h>
#include <tbs.h>
#include "inlineFn.h"

// get the TPM version
HRESULT TpmAttiGetTpmVersion(
	_Out_ PUINT32 pTpmVersion
	);

// read TPM nvram index
HRESULT TpmNVReadValue(
	UINT32 nvIndex,
	_Out_writes_to_opt_(cbData, *pcbResult) PBYTE pbData,
	UINT32 cbData,
	_Out_ PUINT32 pcbResult
	);

// read TPM nvram - tpm 1.2
HRESULT
nvReadVaule12(
TBS_HCONTEXT hPlatformTbsHandle,
UINT32 index,
_In_reads_(cbIndexAuth) PBYTE pbOwnerAuth,
UINT32 cbOwnerAuth,
_Out_writes_to_opt_(cbOutput, *pSize) PBYTE pbOutput,
UINT32 cbOutput,
_Out_ PUINT32 pSize
);

/* PCR extend */
HRESULT TpmPCRExtend(
	UINT32 pcrIndex,
	PBYTE pbDigest,
	_Out_ PBYTE pbNewDigest
	);

/* PCR extend - tpm 1.2 */
HRESULT
pcrExtend12(
TBS_HCONTEXT hPlatformTbsHandle,
UINT32 pcrIndex,
_In_ PBYTE pbDigest,
_Out_ PBYTE pbNewDigest
);
#endif