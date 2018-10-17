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
		if (FAILED(hr = pcrExtend20(hPlatformTbsHandle, pcrIndex, pbDigest, pbNewDigest)))
		{
			goto Cleanup;
		}
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

/* PCR extend - TPM 2.0 */
HRESULT pcrExtend20(
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

	// Build TPM2_PCR_EXTEND command buffer
	if (FAILED(hr = WriteBigEndianUINT16(cmd, sizeof(cmd), &cursorCmd, (UINT16)0x8002))) //TPMI_ST_COMMAND_TAG - TPM_ST_SESSIONS
	{
		goto Cleanup;
	}
	if (FAILED(hr = WriteBigEndianUINT32(cmd, sizeof(cmd), &cursorCmd, (UINT32)0x00000022))) //UINT32 - commandSize
	{
		goto Cleanup;
	}
	if (FAILED(hr = WriteBigEndianUINT32(cmd, sizeof(cmd), &cursorCmd, (UINT32)0x00000182))) //TPM_CC - TPM_CC_PCR_EXTEND
	{
		goto Cleanup;
	}
	if (FAILED(hr = WriteBigEndianUINT32(cmd, sizeof(cmd), &cursorCmd, (UINT32)pcrIndex))) //TPMI_DH_PCR+, handle of the PCR
	{
		goto Cleanup;
	}

	/* authorization part
	   1. auth size
	   2. auth area
	     * session handle: 4 octets
		 * size field: 2 octets - indicating number of octets in nonce
		 * nonce 
		 * session attributes: 1 octets 
		 * size field: 2 octets - indicating the number of octets in authorization
		 * authorization
	 */
	if (FAILED(hr = WriteBigEndianUINT32(cmd, sizeof(cmd), &cursorCmd, (UINT32)(
		sizeof(UINT32) + // sessionHandle
		sizeof(UINT16) + // nonceSize
		sizeof(BYTE) + // session attributes
		sizeof(UINT16) // authSize
		))))
	{
		goto Cleanup;
	}
	if (FAILED(hr = WriteBigEndianUINT32(cmd, sizeof(cmd), &cursorCmd, (UINT32)0x40000009))) //TPM_RS_PW 
	{
		goto Cleanup;
	}

	if (FAILED(hr = WriteBigEndianUINT16(cmd, sizeof(cmd), &cursorCmd, (UINT16)(0x0000))))
	{
		goto Cleanup;
	}

	if (FAILED(hr = WriteBigEndianByte(cmd, sizeof(cmd), &cursorCmd, (BYTE)(0x00))))
	{
		goto Cleanup;
	}

	if (FAILED(hr = WriteBigEndianUINT16(cmd, sizeof(cmd), &cursorCmd, (UINT16)(0x0000))))
	{
		goto Cleanup;
	}

	/* TPML_DIGEST_VALUES - handle of the PCR
		count		UINT32	number of digests in the list
		digests[count]{:HASH_COUNT}	TPMT_HA	a list of taggegd digests (consisting of the hash alg id and the acutal hash
	 */
	if (FAILED(hr = WriteBigEndianUINT32(cmd, sizeof(cmd), &cursorCmd, (UINT32)0x00000001))) // count, only 1 digest for SHA1 for now
	{
		goto Cleanup;
	}
	// TPMT_HA - hashAlg - TPM_ALG_SHA1
	if (FAILED(hr = WriteBigEndianUINT16(cmd, sizeof(cmd), &cursorCmd, (UINT16)0x0004))) //TPM_ALG_SHA1
	{
		goto Cleanup;
	}
	//TPMT_HA - digest data
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
	if (FAILED(hr = ReadBigEndianUINT32(rsp, cbRsp, &cursorRsp, &paramSize))) // responseSize
	{
		goto Cleanup;
	}
	/*
	if (paramSize != cbRsp)
	{
		hr = E_FAIL;
		goto Cleanup;
	}
	*/
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
	/* TPM2_PCR_Extend does not return the PCR value after the command is finished
	if (FAILED(hr = ReadBigEndianBytes(rsp, cbRsp, &cursorRsp, &pbOutDigest, 20))) // data
	{
		goto Cleanup;
	}
	memcpy_s(pbNewDigest, 20, pbOutDigest, 20);
	*/
Cleanup:
	return hr;
}