#include "tpmapi.h"

HRESULT TpmAttiGetTpmVersion(
	_Out_ PUINT32 pTpmVersion
	)
{
	HRESULT hr = S_OK;
	TPM_DEVICE_INFO info = { 0 };

	if (pTpmVersion == NULL)
	{
		hr = E_INVALIDARG;
		goto Cleanup;
	}

	if (FAILED(hr = Tbsi_GetDeviceInfo(sizeof(info), (PVOID)&info)))
	{
		goto Cleanup;
	}

	*pTpmVersion = info.tpmVersion;

Cleanup:
	return hr;
}

HRESULT TpmNVReadValue(
	UINT32 nvIndex,
	_Out_writes_to_opt_(cbData, *pcbResult) PBYTE pbData,
	UINT32 cbData,
	_Out_ PUINT32 pcbResult
	)
{
	HRESULT hr = 0;
	TBS_CONTEXT_PARAMS2 contextParams;
	TBS_HCONTEXT hPlatformTbsHandle = 0;
	UINT32 tpmVersion;
	BYTE pbOwnerAuth[256] = { 0 };
	UINT32 cbOwnerAuth = 256;

	// Get TPM version to select implementation
	if (FAILED(hr = TpmAttiGetTpmVersion(&tpmVersion)))
	{
		goto Cleanup;
	}
	//get the tbs handle
	contextParams.version = TBS_CONTEXT_VERSION_TWO;
	contextParams.asUINT32 = 0;
	contextParams.includeTpm12 = 1;
	contextParams.includeTpm20 = 1;
	if (FAILED(hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&contextParams, &hPlatformTbsHandle)))
	{
		goto Cleanup;
	}

	/* get ownerAuth
	if (FAILED(hr = Tbsi_Get_OwnerAuth(hPlatformTbsHandle, TBS_OWNERAUTH_TYPE_FULL, pbOwnerAuth, &cbOwnerAuth))) {
		goto Cleanup;
	}
	*/

	if (tpmVersion == TPM_VERSION_12)
	{
		
		if (FAILED(hr = nvReadVaule12(hPlatformTbsHandle, nvIndex, pbOwnerAuth, cbOwnerAuth, pbData, cbData, pcbResult)))
		{
			goto Cleanup;
		}
		//wprintf(L"TPM nvdefine returned successfully!\n");
	}
	else if (tpmVersion == TPM_VERSION_20)
	{
		//Not implemented yet
	}
	else
	{
		hr = E_FAIL;
		goto Cleanup;
	}

Cleanup:
	// Close the TBS handle if we opened it in here
	if (hPlatformTbsHandle != NULL)
	{
		Tbsip_Context_Close(hPlatformTbsHandle);
		hPlatformTbsHandle = NULL;
	}
	return hr;
}

HRESULT
nvReadVaule12(
	TBS_HCONTEXT hPlatformTbsHandle,
	UINT32 index,
	_In_reads_(cbIndexAuth) PBYTE pbOwnerAuth,
	UINT32 cbOwnerAuth,
	_Out_writes_to_opt_(cbOutput, *pSize) PBYTE pbData,
	UINT32 cbData,
	_Out_ PUINT32 pSize
)
{

#define SHA1_DIGEST_SIZE 20
	HRESULT hr = S_OK;
	BYTE cmd[0x200] = { 0 };
	BYTE rsp[0x200] = { 0 };
	UINT32 cbRsp = sizeof(rsp);
	UINT32 cursorCmd = 0;
	UINT32 cursorRsp = 0;
	UINT32 paramSize = 0;
	UINT32 returnCode = 0;

	PBYTE pRspData = NULL;

	// Check the parameters
	if ((hPlatformTbsHandle == NULL) ||
		(pbData == NULL))
	{
		hr = E_INVALIDARG;
		goto Cleanup;
	}

	// Build TPM_NV_WRITEVALUEAUTH command buffer
	if (FAILED(hr = WriteBigEndianUINT16(cmd, sizeof(cmd), &cursorCmd, (UINT16)0x00c1))) //1 TPM_TAG_RQU_COMMAND
	{
		goto Cleanup;
	}
	if (FAILED(hr = WriteBigEndianUINT32(cmd, sizeof(cmd), &cursorCmd, (UINT32)0x00000016))) //2 paramSize
	{
		goto Cleanup;
	}
	if (FAILED(hr = WriteBigEndianUINT32(cmd, sizeof(cmd), &cursorCmd, (UINT32)0x000000cf))) //3 TPM_ORD_NV_ReadValue
	{
		goto Cleanup;
	}
	if (FAILED(hr = WriteBigEndianUINT32(cmd, sizeof(cmd), &cursorCmd, (UINT32)index))) //4 TPM_NV_INDEX
	{
		goto Cleanup;
	}
	if (FAILED(hr = WriteBigEndianUINT32(cmd, sizeof(cmd), &cursorCmd, (UINT32)0))) //5 offset = 0;
	{
		goto Cleanup;
	}
	if (FAILED(hr = WriteBigEndianUINT32(cmd, sizeof(cmd), &cursorCmd, (UINT32)cbData))) //6 datasize
	{
		goto Cleanup;
	}

	// Send the command to the TPM
	if (FAILED(hr = Tbsip_Submit_Command(hPlatformTbsHandle,
		TBS_COMMAND_LOCALITY_ZERO,
		TBS_COMMAND_PRIORITY_NORMAL,
		cmd,
		cursorCmd,
		rsp,
		&cbRsp)))
	{
		goto Cleanup;
	}

	// Parse the response
	if (FAILED(hr = SkipBigEndian(rsp, cbRsp, &cursorRsp, sizeof(UINT16)))) // skip tag
	{
		goto Cleanup;
	}
	if (FAILED(hr = ReadBigEndianUINT32(rsp, cbRsp, &cursorRsp, &paramSize))) // paramSize
	{
		goto Cleanup;
	}
	if (paramSize != cbRsp)
	{
		hr = E_FAIL;
		goto Cleanup;
	}
	if (FAILED(hr = ReadBigEndianUINT32(rsp, cbRsp, &cursorRsp, &returnCode))) // ReturnCode
	{
		goto Cleanup;
	}
	if (returnCode != 0)
	{
		//wprintf(L"TPM command failed with return code: %08x\n", returnCode);
		hr = E_FAIL;
		goto Cleanup;
	}
	if (FAILED(hr = ReadBigEndianUINT32(rsp, cbRsp, &cursorRsp, pSize))) // dataSize
	{
		goto Cleanup;
	}
	if (FAILED(hr = ReadBigEndianBytes(rsp, cbRsp, &cursorRsp, &pRspData, *pSize))) // data
	{
		goto Cleanup;
	}
	memcpy_s(pbData, cbData, pRspData, *pSize);

Cleanup:
	return hr;
}

/* TPM PCR extend*/
HRESULT TpmPCRExtend(
	UINT32 pcrIndex,
	PBYTE pbDigest,
	_Out_ PBYTE pbNewDigest
	)
{
	HRESULT hr = 0;
	TBS_CONTEXT_PARAMS2 contextParams;
	TBS_HCONTEXT hPlatformTbsHandle = 0;
	UINT32 tpmVersion;

	// Get TPM version to select implementation
	if (FAILED(hr = TpmAttiGetTpmVersion(&tpmVersion)))
	{
		goto Cleanup;
	}
	//get the tbs handle
	contextParams.version = TBS_CONTEXT_VERSION_TWO;
	contextParams.asUINT32 = 0;
	contextParams.includeTpm12 = 1;
	contextParams.includeTpm20 = 1;
	if (FAILED(hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&contextParams, &hPlatformTbsHandle)))
	{
		goto Cleanup;
	}

	if (tpmVersion == TPM_VERSION_12)
	{
		if (FAILED(hr = pcrExtend12(hPlatformTbsHandle, pcrIndex, pbDigest, pbNewDigest)))
		{
			goto Cleanup;
		}
		//wprintf(L"TPM nvdefine returned successfully!\n");
	}
	else if (tpmVersion == TPM_VERSION_20)
	{
		//Not implemented yet
	}
	else {
		hr = E_FAIL;
		goto Cleanup;
	}

Cleanup:
	// Close the TBS handle if we opened it in here
	if (hPlatformTbsHandle != NULL)
	{
		Tbsip_Context_Close(hPlatformTbsHandle);
		hPlatformTbsHandle = NULL;
	}
	return hr;
}


/* PCR extend - TPM 1.2 */
HRESULT pcrExtend12(
	TBS_HCONTEXT hPlatformTbsHandle,
	UINT32 pcrIndex,
	_In_ PBYTE pbDigest,
	_Out_ PBYTE pbNewDigest
	)
{
	HRESULT hr = S_OK;
	BYTE cmd[0x200] = { 0 };
	BYTE rsp[0x200] = { 0 };
	UINT32 cbRsp = sizeof(rsp);
	UINT32 cursorCmd = 0;
	UINT32 cursorRsp = 0;
	UINT32 paramSize = 0;
	UINT32 returnCode = 0;
	PBYTE pbOutDigest = NULL;

	// Check the parameters
	if ((hPlatformTbsHandle == NULL) ||
		(pbDigest == NULL) ||
		(pbNewDigest == NULL))
	{
		hr = E_INVALIDARG;
		goto Cleanup;
	}

	// Build TPM_EXTEND command buffer
	if (FAILED(hr = WriteBigEndianUINT16(cmd, sizeof(cmd), &cursorCmd, (UINT16)0x00c1))) //TPM_TAG_RQU_COMMAND
	{
		goto Cleanup;
	}
	if (FAILED(hr = WriteBigEndianUINT32(cmd, sizeof(cmd), &cursorCmd, (UINT32)0x00000022))) //paramSize
	{
		goto Cleanup;
	}
	if (FAILED(hr = WriteBigEndianUINT32(cmd, sizeof(cmd), &cursorCmd, (UINT32)0x00000014))) //TPM_ORD_Extend
	{
		goto Cleanup;
	}
	if (FAILED(hr = WriteBigEndianUINT32(cmd, sizeof(cmd), &cursorCmd, (UINT32)pcrIndex))) //TPM_PCRINDEX
	{
		goto Cleanup;
	}
	if (FAILED(hr = WriteBigEndianBytes(cmd, sizeof(cmd), &cursorCmd, pbDigest, 20))) //TPM_DIGEST
	{
		goto Cleanup;
	}

	// Set the command size
	ENDIANSWAP_UINT32TOARRAY(cursorCmd, cmd, 0x0002); // Location of paramSize

	// Send the command to the TPM
	if (FAILED(hr = Tbsip_Submit_Command(hPlatformTbsHandle,
		TBS_COMMAND_LOCALITY_ZERO,
		TBS_COMMAND_PRIORITY_NORMAL,
		cmd,
		cursorCmd,
		rsp,
		&cbRsp)))
	{
		goto Cleanup;
	}

	// Parse the response
	if (FAILED(hr = SkipBigEndian(rsp, cbRsp, &cursorRsp, sizeof(UINT16)))) // skip tag
	{
		goto Cleanup;
	}
	if (FAILED(hr = ReadBigEndianUINT32(rsp, cbRsp, &cursorRsp, &paramSize))) // paramSize
	{
		goto Cleanup;
	}
	if (paramSize != cbRsp)
	{
		hr = E_FAIL;
		goto Cleanup;
	}
	if (FAILED(hr = ReadBigEndianUINT32(rsp, cbRsp, &cursorRsp, &returnCode))) // ReturnCode
	{
		goto Cleanup;
	}
	if (returnCode != 0)
	{
		//wprintf(L"TPM command failed with return code: %08x\n", returnCode);
		hr = E_FAIL;
		goto Cleanup;
	}
	if (FAILED(hr = ReadBigEndianBytes(rsp, cbRsp, &cursorRsp, &pbOutDigest, 20))) // data
	{
		goto Cleanup;
	}
	memcpy_s(pbNewDigest, 20, pbOutDigest, 20);

Cleanup:
	return hr;
}