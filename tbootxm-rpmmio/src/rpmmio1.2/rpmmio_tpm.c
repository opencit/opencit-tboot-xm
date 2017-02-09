/*
 * rpmmio_tpm.c: TPM-related support functions
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
#include "tpm.h"
#include "io.h"
//#include "processor.h"
#include <asm/processor.h>

/* un-comment to enable detailed command tracing */
//#define TPM_TRACE

/* ~5 secs are required for Infineon that requires this, so leave some extra */
#define MAX_SAVESTATE_RETRIES       60

#define TPM_TAG_RQU_COMMAND         0x00C1
#define TPM_TAG_RQU_AUTH1_COMMAND   0x00C2
#define TPM_TAG_RQU_AUTH2_COMMAND   0x00C3
#define TPM_ORD_PCR_EXTEND          0x00000014
#define TPM_ORD_PCR_READ            0x00000015
#define TPM_ORD_PCR_RESET           0x000000C8
#define TPM_ORD_NV_READ_VALUE       0x000000CF
#define TPM_ORD_NV_WRITE_VALUE      0x000000CD
#define TPM_ORD_GET_CAPABILITY      0x00000065
#define TPM_ORD_SEAL                0x00000017
#define TPM_ORD_UNSEAL              0x00000018
#define TPM_ORD_OSAP                0x0000000B
#define TPM_ORD_OIAP                0x0000000A
#define TPM_ORD_SAVE_STATE          0x00000098
#define TPM_ORD_GET_RANDOM          0x00000046

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
#define TIMEOUT_C       750  /* 750ms */
#define TIMEOUT_D       750  /* 750ms */

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
        return TPM_FAIL;
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
        return TPM_FAIL;
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
    return TPM_SUCCESS;

RelinquishControl:
    /* deactivate current locality */
    reg_acc._raw[0] = 0;
    reg_acc.active_locality = 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    return TPM_FAIL;
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
        return TPM_BAD_PARAMETER;
    }
    if ( in == NULL || out == NULL || out_size == NULL ) {
        printk(KERN_WARNING"TPM: Invalid parameter for tpm_write_cmd_fifo()\n");
        return TPM_BAD_PARAMETER;
    }
    if ( in_size < CMD_HEAD_SIZE || *out_size < RSP_HEAD_SIZE ) {
        printk(KERN_WARNING"TPM: in/out buf size must be larger than 10 bytes\n");
        return TPM_BAD_PARAMETER;
    }

    if ( !tpm_validate_locality(locality) ) {
        printk(KERN_ERR"TPM: Locality %d is not open\n", locality);
        return TPM_FAIL;
    }

    ret = tpm_wait_cmd_ready(locality);
    if ( ret != TPM_SUCCESS )
        return ret;

#ifdef TPM_TRACE
    {
        printk(KERN_KERN"TPM: cmd size = %d\nTPM: cmd content: ", in_size);
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
            ret = TPM_FAIL;
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
        ret = TPM_FAIL;
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
        ret = TPM_FAIL;
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
            ret = TPM_FAIL;
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
        return TPM_BAD_PARAMETER;
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
        return TPM_BAD_PARAMETER;
    }

    /* copy tag, size & ordinal into buf in a reversed byte order */
    reverse_copy(cmd_buf, &tag, sizeof(tag));
    reverse_copy(cmd_buf + CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));
    reverse_copy(cmd_buf + CMD_ORD_OFFSET, &cmd, sizeof(cmd));


	printk(KERN_INFO "cmd_buf ready, call tpm_write_cmd_fifo next\n");
	
    rsp_size = RSP_HEAD_SIZE + *out_size;
    rsp_size = (rsp_size > TPM_RSP_SIZE_MAX) ? TPM_RSP_SIZE_MAX: rsp_size;
    ret = tpm_write_cmd_fifo(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size);

	printk(KERN_INFO "after tpm_write_cmd_fifo, ret=%d\n", ret);

    /*
     * should subtract 10 bytes from real response size:
     *      2 bytes for tag
     *      4 bytes for size
     *      4 bytes for return code
     */
    rsp_size -= (rsp_size > RSP_HEAD_SIZE) ? RSP_HEAD_SIZE : rsp_size;

    if ( ret != TPM_SUCCESS )
        return ret;

    if ( *out_size == 0 || rsp_size == 0 )
        *out_size = 0;
    else
        *out_size = (rsp_size < *out_size) ? rsp_size : *out_size;

    return ret;
}

static inline uint32_t tpm_submit_cmd(uint32_t locality, uint32_t cmd,
                                      uint32_t arg_size, uint32_t *out_size)
{
   return  _tpm_submit_cmd(locality, TPM_TAG_RQU_COMMAND, cmd,
                           arg_size, out_size);
}

uint32_t tpm_pcr_extend(uint32_t locality, uint32_t pcr,
                        const tpm_digest_t* in, tpm_pcr_value_t* out)
{
    uint32_t ret, in_size = 0, out_size;

	printk(KERN_INFO "extend to locality %d, pcr %d\n", locality, pcr);
	PrintBytes("in-digest:", in->digest, 20);

    if ( in == NULL )
        return TPM_BAD_PARAMETER;
    if ( pcr >= TPM_NR_PCRS )
        return TPM_BAD_PARAMETER;
    if ( out == NULL )
        out_size = 0;
    else
        out_size = sizeof(*out);

    /* copy pcr into buf in reversed byte order, then copy in data */
    reverse_copy(WRAPPER_IN_BUF, &pcr, sizeof(pcr));
    in_size += sizeof(pcr);
    memcpy(WRAPPER_IN_BUF + in_size, (void *)in, sizeof(*in));
    in_size += sizeof(*in);

    ret = tpm_submit_cmd(locality, TPM_ORD_PCR_EXTEND, in_size, &out_size);

#ifdef TPM_TRACE
    printk(KERN_INFO"TPM: Pcr %d extend, return value = %08X\n", pcr, ret);
#endif
    if ( ret != TPM_SUCCESS ) {
        printk(KERN_INFO "TPM: Pcr %d extend, return value = %08X\n", pcr, ret);
        return ret;
    }

    if ( out != NULL && out_size > 0 ) {
       out_size = (out_size > sizeof(*out)) ? sizeof(*out) : out_size;
       memcpy((void *)out, WRAPPER_OUT_BUF, out_size);
    }

		PrintBytes("TPM after extension, out:", out->digest, 20);

#ifdef TPM_TRACE
    {
        printk(KERN_INFO"TPM: ");
        print_hex(NULL, out->digest, out_size);
    }
#endif

    return ret;
}

uint32_t tpm_pcr_read(uint32_t locality, uint32_t pcr, tpm_pcr_value_t *out)
{
    uint32_t ret, out_size = sizeof(*out);

    if ( out == NULL )
        return TPM_BAD_PARAMETER;
    if ( pcr >= TPM_NR_PCRS )
        return TPM_BAD_PARAMETER;

    /* copy pcr into buf in reversed byte order */
    reverse_copy(WRAPPER_IN_BUF, &pcr, sizeof(pcr));

    ret = tpm_submit_cmd(locality, TPM_ORD_PCR_READ, sizeof(pcr), &out_size);

#ifdef TPM_TRACE
    //printk(TBOOT_DETA"TPM: Pcr %d Read return value = %08X\n", pcr, ret);
#endif
    if ( ret != TPM_SUCCESS ) {
        printk(KERN_ERR"TPM: Pcr %d Read not successful, return value = %08X\n", pcr, ret);
        return ret;
    }

    if ( out_size > sizeof(*out) )
        out_size = sizeof(*out);
    memcpy((void *)out, WRAPPER_OUT_BUF, out_size);

#ifdef TPM_TRACE
    {
        printk(KERN_INFO"TPM: ");
        print_hex(NULL, out->digest, out_size);
    }
#endif

    return ret;
}

