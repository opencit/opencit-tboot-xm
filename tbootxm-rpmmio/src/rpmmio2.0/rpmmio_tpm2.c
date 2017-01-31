/*
 * rpmmio_tpm2.c: TPM2.0-related support functions
 *
 * Copyright (c) 2006-2010, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include<linux/kernel.h>
#include "tpm2.h"
#include "io.h"
//#include "processor.h"
#include <asm/processor.h>

/* un-comment to enable detailed command tracing */
//#define TPM_TRACE

/* ~5 secs are required for Infineon that requires this, so leave some extra */
#define MAX_SAVESTATE_RETRIES       60

#define TPM_CC_PCR_EXTEND           0x00000182
#define TPM_CC_PCR_READ             0x0000017E
#define TPM_CC_PCR_RESET            0x0000013D
#define TPM_CC_NV_READ              0x0000014E
#define TPM_CC_NV_WRITE             0x00000137
#define TPM_CC_GET_RANDOM           0x0000017B

#define TPM_TAG_PCR_INFO_LONG       0x0006
#define TPM_TAG_STORED_DATA12       0x0016

void PrintBytes(const char* szMsg, unsigned char* pbData, int iSize)
{
	    int i;
	int col=32;
	
    printk(KERN_INFO "%s", szMsg);
    for (i= 0; i<iSize; i++) {
        printk(KERN_INFO "%02x", pbData[i]);
        if((i%col)==(col-1))
            printk(KERN_INFO "\n");
        }
    printk(KERN_INFO "\n");
}

/*
 * TPM registers and data structures
 *
 * register values are offsets from each locality base
 * see {read,write}_tpm_reg() for data struct format
 */

/* TPM_ACCESS_x */
#define TPM_REG_ACCESS           0x00
typedef union {
    u8 _raw[1];                      /* 1-byte reg */
    struct __packed {
        u8 tpm_establishment   : 1;  /* RO, 0=T/OS has been established
                                        before */
        u8 request_use         : 1;  /* RW, 1=locality is requesting TPM use */
        u8 pending_request     : 1;  /* RO, 1=other locality is requesting
                                        TPM usage */
        u8 seize               : 1;  /* WO, 1=seize locality */
        u8 been_seized         : 1;  /* RW, 1=locality seized while active */
        u8 active_locality     : 1;  /* RW, 1=locality is active */
        u8 reserved            : 1;
        u8 tpm_reg_valid_sts   : 1;  /* RO, 1=other bits are valid */
    };
} tpm_reg_access_t;

/* TPM_STS_x */
#define TPM_REG_STS              0x18
typedef union {
    u8 _raw[3];                  /* 3-byte reg */
    struct __packed {
        u8 reserved1       : 1;
        u8 response_retry  : 1;  /* WO, 1=re-send response */
        u8 reserved2       : 1;
        u8 expect          : 1;  /* RO, 1=more data for command expected */
        u8 data_avail      : 1;  /* RO, 0=no more data for response */
        u8 tpm_go          : 1;  /* WO, 1=execute sent command */
        u8 command_ready   : 1;  /* RW, 1=TPM ready to receive new cmd */
        u8 sts_valid       : 1;  /* RO, 1=data_avail and expect bits are
                                    valid */
        u16 burst_count    : 16; /* RO, # read/writes bytes before wait */
    };
} tpm_reg_sts_t;

/* TPM_DATA_FIFO_x */
#define TPM_REG_DATA_FIFO        0x24
typedef union {
        uint8_t _raw[1];                      /* 1-byte reg */
} tpm_reg_data_fifo_t;

/*
 * assumes that all reg types follow above format:
 *   - packed
 *   - member named '_raw' which is array whose size is that of data to read
 */
#define read_tpm_reg(locality, reg, pdata)      \
    _read_tpm_reg(locality, reg, (pdata)->_raw, sizeof(*(pdata)))

#define write_tpm_reg(locality, reg, pdata)     \
    _write_tpm_reg(locality, reg, (pdata)->_raw, sizeof(*(pdata)))

extern void* g_tpm_base;
int log=1;
static ulong TPM_LOCALITY_BASE_N(int locality)
{
	ulong ret = (ulong)g_tpm_base | (locality) << 12 ;
	if(log==1){
		printk(KERN_INFO "TPM_LOCALITY_BASE_N for locality %d is %lx\n", locality, ret);
		log=0;
	}
		return ((ulong)g_tpm_base | (locality) << 12 ); 
}

static void _read_tpm_reg(int locality, u32 reg, u8 *_raw, size_t size)
{
	size_t i;
    for (i = 0; i < size; i++ )
        _raw[i] = readb((TPM_LOCALITY_BASE_N(locality) | reg) + i);
}

static void _write_tpm_reg(int locality, u32 reg, u8 *_raw, size_t size)
{
	size_t i;
    for ( i = 0; i < size; i++ )
        writeb((TPM_LOCALITY_BASE_N(locality) | reg) + i, _raw[i]);
}

/*
 * the following inline function reversely copy the bytes from 'in' to
 * 'out', the byte number to copy is given in count.
 */
#define reverse_copy(out, in, count) \
    _reverse_copy((uint8_t *)(out), (uint8_t *)(in), count)

static inline void _reverse_copy(uint8_t *out, uint8_t *in, uint32_t count)
{
	uint32_t i;
    for ( i = 0; i < count; i++ )
        out[i] = in[count - i - 1];
}

#define TPM_VALIDATE_LOCALITY_TIME_OUT  0x100

static bool tpm_validate_locality(uint32_t locality)
{
    uint32_t i;
    tpm_reg_access_t reg_acc;

    for ( i = TPM_VALIDATE_LOCALITY_TIME_OUT; i > 0; i-- ) {
        /*
         * TCG spec defines reg_acc.tpm_reg_valid_sts bit to indicate whether
         * other bits of access reg are valid.( but this bit will also be 1
         * while this locality is not available, so check seize bit too)
         * It also defines that reading reg_acc.seize should always return 0
         */
        read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
        if ( reg_acc.tpm_reg_valid_sts == 1 && reg_acc.seize == 0)
            return true;
        cpu_relax();
    }

    if ( i <= 0 )
        printk(KERN_ERR "TPM: tpm_validate_locality timeout\n");

    return false;
}

#define TIMEOUT_UNIT    (0x100000 / 330) /* ~1ms, 1 tpm r/w need > 330ns */
#define TIMEOUT_A       750  /* 750ms */
#define TIMEOUT_B       2000 /* 2s */
#define TIMEOUT_C       200  /* 750ms */
#define TIMEOUT_D       30  /* 750ms */

typedef struct __packed {
    uint32_t timeout_a;
    uint32_t timeout_b;
    uint32_t timeout_c;
    uint32_t timeout_d;
} tpm_timeout_t;

static tpm_timeout_t g_timeout = {TIMEOUT_A,
                                  TIMEOUT_B,
                                  TIMEOUT_C,
                                  TIMEOUT_D};

#define TPM_ACTIVE_LOCALITY_TIME_OUT    \
          (TIMEOUT_UNIT * g_timeout.timeout_a)  /* according to spec */
#define TPM_CMD_READY_TIME_OUT          \
          (TIMEOUT_UNIT * g_timeout.timeout_b)  /* according to spec */
#define TPM_CMD_WRITE_TIME_OUT          \
          (TIMEOUT_UNIT * g_timeout.timeout_d)  /* let it long enough */
#define TPM_DATA_AVAIL_TIME_OUT         \
          (TIMEOUT_UNIT * g_timeout.timeout_c)  /* let it long enough */
#define TPM_RSP_READ_TIME_OUT           \
          (TIMEOUT_UNIT * g_timeout.timeout_d)  /* let it long enough */

static uint32_t tpm_wait_cmd_ready(uint32_t locality)
{
    uint32_t            i;
    tpm_reg_access_t    reg_acc;
    tpm_reg_sts_t       reg_sts;

    /* ensure the contents of the ACCESS register are valid */
    read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
#ifdef TPM_TRACE
    printk(KERN_INFO"TPM: Access reg content: 0x%02x\n", (uint32_t)reg_acc._raw[0]);
#endif
    if ( reg_acc.tpm_reg_valid_sts == 0 ) {
        printk(KERN_ERR"TPM: Access reg not valid\n");
        return TPM_RC_FAILURE;
    }

    /* request access to the TPM from locality N */
    reg_acc._raw[0] = 0;
    reg_acc.request_use = 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    i = 0;
    do {
        read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
        if ( reg_acc.active_locality == 1 )
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_ACTIVE_LOCALITY_TIME_OUT);

    if ( i > TPM_ACTIVE_LOCALITY_TIME_OUT ) {
        printk(KERN_ERR"TPM: access reg request use timeout\n");
        return TPM_RC_FAILURE;
    }

    /* ensure the TPM is ready to accept a command */
#ifdef TPM_TRACE
    printk(KERN_INFO"TPM: wait for cmd ready ");
#endif
    i = 0;
    do {
        /* write 1 to TPM_STS_x.commandReady to let TPM enter ready state */
        memset((void *)&reg_sts, 0, sizeof(reg_sts));
        reg_sts.command_ready = 1;
        write_tpm_reg(locality, TPM_REG_STS, &reg_sts);
        cpu_relax();

        /* then see if it has */
        read_tpm_reg(locality, TPM_REG_STS, &reg_sts);
#ifdef TPM_TRACE
        printk(KERN_INFO".");
#endif
        if ( reg_sts.command_ready == 1 )
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_CMD_READY_TIME_OUT );
#ifdef TPM_TRACE
    printk(KERN_INFO"\n");
#endif

    if ( i > TPM_CMD_READY_TIME_OUT ) {
        printk(KERN_INFO"TPM: status reg content: %02x %02x %02x\n",
               (uint32_t)reg_sts._raw[0],
               (uint32_t)reg_sts._raw[1],
               (uint32_t)reg_sts._raw[2]);
        printk(KERN_INFO"TPM: tpm timeout for command_ready\n");
        goto RelinquishControl;
    }
    return TPM_RC_SUCCESS;

RelinquishControl:
    /* deactivate current locality */
    reg_acc._raw[0] = 0;
    reg_acc.active_locality = 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    return TPM_RC_FAILURE;
}

/*
 *   locality : TPM locality (0 - 3)
 *   in       : All bytes for a single TPM command, including TAG, SIZE,
 *              ORDINAL, and other arguments. All data should be in big-endian
 *              style. The in MUST NOT be NULL, containing at least 10 bytes.
 *              0   1   2   3   4   5   6   7   8   9   10  ...
 *              -------------------------------------------------------------
 *              | TAG  |     SIZE      |    ORDINAL    |    arguments ...
 *              -------------------------------------------------------------
 *   in_size  : The size of the whole command contained within the in buffer.
 *              It should equal to the SIZE contained in the in buffer.
 *   out      : All bytes of the TPM response to a single command. All data
 *              within it will be in big-endian style. The out MUST not be
 *              NULL, and will return at least 10 bytes.
 *              0   1   2   3   4   5   6   7   8   9   10  ...
 *              -------------------------------------------------------------
 *              | TAG  |     SIZE      |  RETURN CODE  |    other data ...
 *              -------------------------------------------------------------
 *   out_size : In/out paramter. As in, it is the size of the out buffer;
 *              as out, it is the size of the response within the out buffer.
 *              The out_size MUST NOT be NULL.
 *   return   : 0 = success; if not 0, it equal to the RETURN CODE in out buf.
 */
#define CMD_HEAD_SIZE           10
#define RSP_HEAD_SIZE           10
#define CMD_SIZE_OFFSET         2
#define CMD_ORD_OFFSET          6
#define RSP_SIZE_OFFSET         2
#define RSP_RST_OFFSET          6

static uint32_t tpm_write_cmd_fifo(uint32_t locality, uint8_t *in,
                                   uint32_t in_size, uint8_t *out,
                                   uint32_t *out_size)
{
    uint32_t            i, rsp_size, offset, ret;
    uint16_t            row_size;
    tpm_reg_access_t    reg_acc;
    tpm_reg_sts_t       reg_sts;

    if ( locality >= TPM_NR_LOCALITIES ) {
        printk(KERN_WARNING"TPM: Invalid locality for tpm_write_cmd_fifo()\n");
        return TPM_RC_LOCALITY;
    }
    if ( in == NULL || out == NULL || out_size == NULL ) {
        printk(KERN_WARNING"TPM: Invalid parameter for tpm_write_cmd_fifo()\n");
        return TPM_RC_TAG;
    }
    if ( in_size < CMD_HEAD_SIZE || *out_size < RSP_HEAD_SIZE ) {
        printk(KERN_WARNING"TPM: in/out buf size must be larger than 10 bytes\n");
        return TPM_RC_COMMAND_SIZE;
    }

    if ( !tpm_validate_locality(locality) ) {
        printk(KERN_ERR"TPM: Locality %d is not open\n", locality);
        return TPM_RC_FAILURE;
    }

    ret = tpm_wait_cmd_ready(locality);
    if ( ret != TPM_RC_SUCCESS )
        return ret;

#ifdef TPM_TRACE
    {
        printk(KERN_INFO"TPM: cmd size = %d\nTPM: cmd content: ", in_size);
        print_hex("TPM: \t", in, in_size);
    }
#endif

    /* write the command to the TPM FIFO */
    offset = 0;
    do {
        i = 0;
        do {
            read_tpm_reg(locality, TPM_REG_STS, &reg_sts);
            /* find out how many bytes the TPM can accept in a row */
            row_size = reg_sts.burst_count;
            if ( row_size > 0 )
                break;
            else
                cpu_relax();
            i++;
        } while ( i <= TPM_CMD_WRITE_TIME_OUT );
        if ( i > TPM_CMD_WRITE_TIME_OUT ) {
            printk(KERN_ERR"TPM: write cmd timeout\n");
            ret = TPM_RC_FAILURE;
            goto RelinquishControl;
        }

        for ( ; row_size > 0 && offset < in_size; row_size--, offset++ )
            write_tpm_reg(locality, TPM_REG_DATA_FIFO,
                          (tpm_reg_data_fifo_t *)&in[offset]);
    } while ( offset < in_size );

    i = 0;
    do {
        read_tpm_reg(locality,TPM_REG_STS, &reg_sts);
#ifdef TPM_TRACE
        printk(KERN_INFO"Wait on Expect = 0, Status register %02x\n", reg_sts._raw[0]);
#endif
        if ( reg_sts.sts_valid == 1 && reg_sts.expect == 0 )
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_DATA_AVAIL_TIME_OUT );
    if ( i > TPM_DATA_AVAIL_TIME_OUT ) {
        printk(KERN_ERR"TPM: wait for expect becoming 0 timeout\n");
        ret = TPM_RC_FAILURE;
        goto RelinquishControl;
    }

    /* command has been written to the TPM, it is time to execute it. */
    memset(&reg_sts, 0,  sizeof(reg_sts));
    reg_sts.tpm_go = 1;
    write_tpm_reg(locality, TPM_REG_STS, &reg_sts);

    /* check for data available */
    i = 0;
    do {
        read_tpm_reg(locality,TPM_REG_STS, &reg_sts);
#ifdef TPM_TRACE
        printk(KERN_INFO"Waiting for DA Flag, Status register %02x\n", reg_sts._raw[0]);
#endif
        if ( reg_sts.sts_valid == 1 && reg_sts.data_avail == 1 )
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_DATA_AVAIL_TIME_OUT );
    if ( i > TPM_DATA_AVAIL_TIME_OUT ) {
        printk(KERN_ERR"TPM: wait for data available timeout\n");
        ret = TPM_RC_FAILURE;
        goto RelinquishControl;
    }

    rsp_size = 0;
    offset = 0;
    do {
        /* find out how many bytes the TPM returned in a row */
        i = 0;
        do {
            read_tpm_reg(locality, TPM_REG_STS, &reg_sts);
            row_size = reg_sts.burst_count;
            if ( row_size > 0 )
                break;
            else
                cpu_relax();
            i++;
        } while ( i <= TPM_RSP_READ_TIME_OUT );
        if ( i > TPM_RSP_READ_TIME_OUT ) {
            printk(KERN_ERR"TPM: read rsp timeout\n");
            ret = TPM_RC_FAILURE;
            goto RelinquishControl;
        }

        for ( ; row_size > 0 && offset < *out_size; row_size--, offset++ ) {
            if ( offset < *out_size )
                read_tpm_reg(locality, TPM_REG_DATA_FIFO,
                             (tpm_reg_data_fifo_t *)&out[offset]);
            else {
                /* discard the responded bytes exceeding out buf size */
                tpm_reg_data_fifo_t discard;
                read_tpm_reg(locality, TPM_REG_DATA_FIFO,
                             (tpm_reg_data_fifo_t *)&discard);
            }

            /* get outgoing data size */
            if ( offset == RSP_RST_OFFSET - 1 ) {
                reverse_copy(&rsp_size, &out[RSP_SIZE_OFFSET],
                             sizeof(rsp_size));
            }
        }
    } while ( offset < RSP_RST_OFFSET ||
              (offset < rsp_size && offset < *out_size) );

    *out_size = (*out_size > rsp_size) ? rsp_size : *out_size;

    /* out buffer contains the complete outgoing data, get return code */
    reverse_copy(&ret, &out[RSP_RST_OFFSET], sizeof(ret));

#ifdef TPM_TRACE
    {
        printk(KERN_INFO"TPM: response size = %d\n", *out_size);
        printk(KERN_INFO"TPM: response content: ");
        print_hex("TPM: \t", out, *out_size);
    }
#endif

    memset(&reg_sts, 0, sizeof(reg_sts));
    reg_sts.command_ready = 1;
    write_tpm_reg(locality, TPM_REG_STS, &reg_sts);

RelinquishControl:
    /* deactivate current locality */
    reg_acc._raw[0] = 0;
    reg_acc.active_locality = 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    return ret;
}

/*
 * The _tpm_submit_cmd function comes with 2 global buffers: cmd_buf & rsp_buf.
 * Before calling, caller should fill cmd arguements into cmd_buf via
 * WRAPPER_IN_BUF macro. After calling, caller should fetch result from
 * rsp_buffer via WRAPPER_OUT_BUF macro.
 * cmd_buf content:
 *  0   1   2   3   4   5   6   7   8   9   10  ...
 * -------------------------------------------------------------
 * |  TAG  |     SIZE      |    ORDINAL    |    arguments ...
 * -------------------------------------------------------------
 * rsp_buf content:
 *  0   1   2   3   4   5   6   7   8   9   10  ...
 * -------------------------------------------------------------
 * |  TAG  |     SIZE      |  RETURN CODE  |    other data ...
 * -------------------------------------------------------------
 *
 *   locality : TPM locality (0 - 4)
 *   tag      : The TPM command tag
 *   cmd      : The TPM command ordinal
 *   arg_size : Size of argument data.
 *   out_size : IN/OUT paramter. The IN is the expected size of out data;
 *              the OUT is the size of output data within out buffer.
 *              The out_size MUST NOT be NULL.
 *   return   : TPM_SUCCESS for success, for other error code, refer to the .h
 */
static uint8_t     cmd_buf[TPM_CMD_SIZE_MAX];
static uint8_t     rsp_buf[TPM_RSP_SIZE_MAX];
#define WRAPPER_IN_BUF          (cmd_buf + CMD_HEAD_SIZE)
#define WRAPPER_OUT_BUF         (rsp_buf + RSP_HEAD_SIZE)
#define WRAPPER_IN_MAX_SIZE     (TPM_CMD_SIZE_MAX - CMD_HEAD_SIZE)
#define WRAPPER_OUT_MAX_SIZE    (TPM_RSP_SIZE_MAX - RSP_HEAD_SIZE)

static uint32_t _tpm_submit_cmd(uint32_t locality, uint16_t tag, uint32_t cmd,
                               uint32_t arg_size, uint32_t *out_size)
{
    uint32_t    ret;
    uint32_t    cmd_size, rsp_size = 0;

    if ( out_size == NULL ) {
        printk(KERN_WARNING"TPM: invalid param for _tpm_submit_cmd()\n");
        return TPM_RC_TAG;
    }

    /*
     * real cmd size should add 10 more bytes:
     *      2 bytes for tag
     *      4 bytes for size
     *      4 bytes for ordinal
     */
    cmd_size = CMD_HEAD_SIZE + arg_size;

    if ( cmd_size > TPM_CMD_SIZE_MAX ) {
        printk(KERN_WARNING"TPM: cmd exceeds the max supported size.\n");
        return TPM_RC_COMMAND_SIZE;
    }

    /* copy tag, size & ordinal into buf in a reversed byte order */
    reverse_copy(cmd_buf, &tag, sizeof(tag));
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));
    reverse_copy(cmd_buf + CMD_ORD_OFFSET, &cmd, sizeof(cmd));

PrintBytes("TPM: CMD_BUF ", cmd_buf, cmd_size);
	printk(KERN_INFO "cmd_buf ready, call tpm_write_cmd_fifo next\n");
	
    rsp_size = RSP_HEAD_SIZE + *out_size;
    rsp_size = (rsp_size > TPM_RSP_SIZE_MAX) ? TPM_RSP_SIZE_MAX: rsp_size;
    ret = tpm_write_cmd_fifo(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size);

	printk(KERN_INFO "after tpm_write_cmd_fifo, ret=%d\n", ret);
PrintBytes("TPM: RSP_BUF ", rsp_buf, rsp_size);

    /*
     * should subtract 10 bytes from real response size:
     *      2 bytes for tag
     *      4 bytes for size
     *      4 bytes for return code
     */
    rsp_size -= (rsp_size > RSP_HEAD_SIZE) ? RSP_HEAD_SIZE : rsp_size;

    if ( ret != TPM_RC_SUCCESS )
        return ret;

    if ( *out_size == 0 || rsp_size == 0 )
        *out_size = 0;
    else
        *out_size = (rsp_size < *out_size) ? rsp_size : *out_size;

    return ret;
}

static inline uint32_t tpm_submit_cmd(uint32_t locality, uint16_t tag, uint32_t cmd,
                                      uint32_t arg_size, uint32_t *out_size)
{
   return  _tpm_submit_cmd(locality, tag, cmd,
                           arg_size, out_size);
}

extern UINT32 tpm_pcr_extend2(UINT32 locality, tpmi_dh_pcr handle, tpmi_alg_hash hash,
                                UINT32 size, BYTE *data)
{
	UINT32 ret;
	UINT32 in_size = 0;
	UINT32 out_size = 0;
    UINT32 pcr = handle;
	UINT32 auth_size = sizeof(UINT32)+sizeof(UINT16)+sizeof(BYTE)+sizeof(UINT16);

	printk(KERN_INFO "TPM: Pcr %d extend\n", pcr);
	printk(KERN_INFO "TPM: Hash %d extend\n", hash);
	printk(KERN_INFO "TPM: Size %d extend\n", size);
    PrintBytes("TPM: Data ", data, size);

	if (pcr > TPM_NR_PCRS)
		return TPM_RC_VALUE;
	if (pcr == TPM_RH_NULL)
		return TPM_RC_SUCCESS;

	tpmu_ha tu;
	memcpy(tu.sha256, data, size);
	
	tpmt_ha tt;
	tt.hash_alg = hash;
	tt.digest = tu;

	tpml_digest_values tl;
	tl.count = 1;
	tl.digests[0] = tt;

	tpml_digest_values *in = &tl;

	printk(KERN_INFO "TPM: Count %d extend\n", in->count);
	printk(KERN_INFO "TPM: Hash_Alg %d extend\n", in->digests[0].hash_alg);
	PrintBytes("TPM: Digest ", in->digests[0].digest.sha256, size);
	
	tpm2b_digest nonce;
	nonce.size = 0;
	memset(nonce.buffer, 0, nonce.size);

	tpm2b_digest auth;
	auth.size = 0;
	memset(auth.buffer, 0, auth.size);

	tpms_auth_command ts;
	ts.session_handle = TPM_RS_PW;
	ts.nonce = nonce;
	ts.session_attributes = 0;
	ts.auth = auth;

	tpms_auth_command *auth_area = &ts;

	printk(KERN_INFO "TPM: Session_Handle %08X extend\n", auth_area->session_handle);
	printk(KERN_INFO "TPM: Nonce_Size %d extend\n", auth_area->nonce.size);
	printk(KERN_INFO "TPM: Auth_Size %d extend\n", auth_area->auth.size);
	printk(KERN_INFO "TPM: Session_Attributes %d extend\n", auth_area->session_attributes);

	/* copy pcr into buf in reversed byte order, then copy in data */
    	reverse_copy(WRAPPER_IN_BUF, &pcr, sizeof(pcr));
    	in_size += sizeof(pcr);
    	//memcpy(WRAPPER_IN_BUF + in_size, &auth_size, sizeof(auth_size));
    	reverse_copy(WRAPPER_IN_BUF + in_size, &auth_size, sizeof(auth_size));
    	in_size += sizeof(auth_size);
    	reverse_copy(WRAPPER_IN_BUF + in_size, &(ts.session_handle), sizeof(ts.session_handle));
    	in_size += sizeof(ts.session_handle);
    	reverse_copy(WRAPPER_IN_BUF + in_size, &(ts.nonce.size), sizeof(UINT16));
    	in_size += sizeof(UINT16);
    	reverse_copy(WRAPPER_IN_BUF + in_size, &(ts.session_attributes), sizeof(ts.session_attributes));
    	in_size += sizeof(ts.session_attributes);
    	reverse_copy(WRAPPER_IN_BUF + in_size, &(ts.auth.size), sizeof(UINT16));
    	in_size += sizeof(UINT16);
    	//memcpy(WRAPPER_IN_BUF + in_size, (void *)auth_area, 9);
    	//reverse_copy(WRAPPER_IN_BUF + in_size, (void *)auth_area, sizeof(*auth_area));
    	//in_size += 9;
    	//memcpy(WRAPPER_IN_BUF + in_size, (void *)in, sizeof(*in));
    	//in_size += sizeof(*in);
    	//memcpy(WRAPPER_IN_BUF + in_size, (void *)in, 26);
    	//reverse_copy(WRAPPER_IN_BUF + in_size, (void *)in, 26);
    	//in_size += 26;
    	reverse_copy(WRAPPER_IN_BUF + in_size, &(tl.count), sizeof(tl.count));
    	in_size += sizeof(tl.count);
    	reverse_copy(WRAPPER_IN_BUF + in_size, &(tl.digests[0].hash_alg), sizeof(tl.digests[0].hash_alg));
    	in_size += sizeof(tl.digests[0].hash_alg);
    	memcpy(WRAPPER_IN_BUF + in_size, tl.digests[0].digest.sha256, size);
    	in_size += size;

	printk(KERN_INFO "TPM: In_Size %d extend\n", in_size);
	PrintBytes("TPM: WRAPPER_IN_BUF ", WRAPPER_IN_BUF, in_size);
    	
	ret = tpm_submit_cmd(locality, TPM_ST_SESSIONS, TPM_CC_PCR_EXTEND, in_size, &out_size);

#ifdef TPM_TRACE
    	printk(KERN_INFO"TPM: Pcr %d extend, return value = %08X\n", handle, ret);
#endif
    	if ( ret != TPM_RC_SUCCESS ) {
        	printk(KERN_INFO "TPM: Pcr %d extend, return value = %08X\n", handle, ret);
        	return ret;
    	}
		
		printk(KERN_INFO "TPM: Out_Size %d read\n", out_size);
		
    	return ret;
}

extern UINT32 tpm_pcr_read2(UINT32 locality, tpml_pcr_selection *selection,
				tpml_digest *digest, UINT32 pcr_counter)
{
	UINT32 ret;
	UINT32 in_size = 0;
	UINT32 out_size = sizeof(*selection) + sizeof(*digest) + sizeof(pcr_counter);
	
	printk(KERN_INFO "TPM: Selection_Count %d read\n", selection->count);
	printk(KERN_INFO "TPM: Selection_Hash %d read\n", selection->pcr_selections[0].hash);
	printk(KERN_INFO "TPM: Selection_SizeofSelect %d read\n", selection->pcr_selections[0].size_of_select);
	PrintBytes("TPM: Selection_PcrSelect ", selection->pcr_selections[0].pcr_select, selection->pcr_selections[0].size_of_select);
	
	if (selection->count > HASH_COUNT)
		return TPM_RC_SIZE;
        if (selection->pcr_selections[0].size_of_select > PCR_SELECT_MAX)
		return TPM_RC_VALUE;

	/* copy pcr into buf in reversed byte order */
    	//reverse_copy(WRAPPER_IN_BUF, selection, sizeof(*selection));
    	//reverse_copy(WRAPPER_IN_BUF, selection, 10);
    	reverse_copy(WRAPPER_IN_BUF, &(selection->count), sizeof(UINT32));
	in_size += sizeof(UINT32);
    	reverse_copy(WRAPPER_IN_BUF + in_size, &(selection->pcr_selections[0].hash), sizeof(UINT16));
	in_size += sizeof(UINT16);
    	reverse_copy(WRAPPER_IN_BUF + in_size, &(selection->pcr_selections[0].size_of_select), sizeof(UINT8));
	in_size += sizeof(UINT8);
    	memcpy(WRAPPER_IN_BUF + in_size, selection->pcr_selections[0].pcr_select, sizeof(selection->pcr_selections[0].pcr_select));
	in_size += sizeof(selection->pcr_selections[0].pcr_select);
    	
	printk(KERN_INFO "TPM: In_Size %d read\n", in_size);
	PrintBytes("TPM: WRAPPER_IN_BUF ", WRAPPER_IN_BUF, in_size);

	//ret = tpm_submit_cmd(locality, TPM_ST_NO_SESSIONS, TPM_CC_PCR_READ, sizeof(*selection), &out_size);
    	ret = tpm_submit_cmd(locality, TPM_ST_NO_SESSIONS, TPM_CC_PCR_READ, in_size, &out_size);

#ifdef TPM_TRACE
    	printk(KERN_INFO"TPM: Pcr %d Read return value = %08X\n", pcr, ret);
#endif
    	if ( ret != TPM_RC_SUCCESS ) {
        	printk(KERN_INFO"TPM: Pcr %d %d %d Read not successful, return value = %08X\n", selection->pcr_selections[0].pcr_select[0], selection->pcr_selections[0].pcr_select[1], selection->pcr_selections[0].pcr_select[2], ret);
        	return ret;
    	}

	printk(KERN_INFO "TPM: Out_Size %d read\n", out_size);

    	if ( out_size > (sizeof(*selection) + sizeof(*digest) + sizeof(pcr_counter)) )
        	out_size = sizeof(*selection) + sizeof(*digest) + sizeof(pcr_counter);

	in_size = 0;
    	reverse_copy((void *)&pcr_counter, WRAPPER_OUT_BUF, sizeof(pcr_counter));
	printk(KERN_INFO "TPM: Pcr_Counter %d read\n", pcr_counter);
	in_size += sizeof(pcr_counter) + 10;
	//memcpy((void *)digest, WRAPPER_OUT_BUF + in_size, 26);
    	reverse_copy((void *)&(digest->count), WRAPPER_OUT_BUF + in_size, sizeof(digest->count));
	printk(KERN_INFO "TPM: Digest_Count %d read\n", digest->count);
	in_size += sizeof(digest->count);
    	reverse_copy((void *)&(digest->digests[0].size), WRAPPER_OUT_BUF + in_size, sizeof(digest->digests[0].size));
	printk(KERN_INFO "TPM: Digest_Size %d read\n", digest->digests[0].size);
	in_size += sizeof(digest->digests[0].size);
    	memcpy((void *)digest->digests[0].buffer, WRAPPER_OUT_BUF + in_size, digest->digests[0].size);
	PrintBytes("TPM: Digest_Buffer : ", digest->digests[0].buffer, digest->digests[0].size);

#ifdef TPM_TRACE
    	{
        	printk(KERN_INFO"TPM: ");
        	print_hex(NULL, digest->digests[0].buffer, digest->digests[0].size);
    	}
#endif

   	 return ret;
}
