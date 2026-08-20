#pragma once

#include <stdint.h>

/*
 * Self-checksum final-binary binding record, version 1.
 *
 * This is a byte-level ABI.  Do not serialize native C/C++ structs directly;
 * producers and consumers must use the fixed offsets below.
 */
#define OBF_SC_RECORD_MAGIC UINT32_C(0x4353424f) /* bytes: "OBSC" */
#define OBF_SC_RECORD_VERSION UINT16_C(1)
#define OBF_SC_RECORD_SIZE UINT16_C(96)

#define OBF_SC_FLAG_REQUIRED UINT32_C(0x00000001)
#define OBF_SC_FLAG_BOUND UINT32_C(0x00000002)
#define OBF_SC_FLAG_V1_MASK (OBF_SC_FLAG_REQUIRED | OBF_SC_FLAG_BOUND)

#define OBF_SC_ALGORITHM_RT_CORE_CC_V1 UINT32_C(1)
#define OBF_SC_OBJECT_FORMAT_ELF UINT32_C(1)
#define OBF_SC_MACHINE_X86_64 UINT32_C(1)
#define OBF_SC_TARGET_RECORD_REL64 UINT32_C(1)
#define OBF_SC_V1_SAMPLE_OFFSET UINT32_C(0)
#define OBF_SC_V1_MIN_SAMPLE_SIZE UINT32_C(16)
#define OBF_SC_V1_MAX_SAMPLE_SIZE UINT32_C(32)

#define OBF_SC_OFF_MAGIC UINT32_C(0x00)
#define OBF_SC_OFF_VERSION UINT32_C(0x04)
#define OBF_SC_OFF_RECORD_SIZE UINT32_C(0x06)
#define OBF_SC_OFF_FLAGS UINT32_C(0x08)
#define OBF_SC_OFF_ALGORITHM UINT32_C(0x0c)
#define OBF_SC_OFF_OBJECT_FORMAT UINT32_C(0x10)
#define OBF_SC_OFF_MACHINE UINT32_C(0x14)
#define OBF_SC_OFF_SITE_ID UINT32_C(0x18)
#define OBF_SC_OFF_TARGET_DELTA UINT32_C(0x20)
#define OBF_SC_OFF_TARGET_KIND UINT32_C(0x28)
#define OBF_SC_OFF_SAMPLE_OFFSET UINT32_C(0x2c)
#define OBF_SC_OFF_SAMPLE_SIZE UINT32_C(0x30)
#define OBF_SC_OFF_RESERVED0 UINT32_C(0x34)
#define OBF_SC_OFF_SEED UINT32_C(0x38)
#define OBF_SC_OFF_EXPECTED_CHECKSUM UINT32_C(0x40)
#define OBF_SC_OFF_RESERVED1 UINT32_C(0x48)
#define OBF_SC_RESERVED1_SIZE UINT32_C(24)

#define OBF_SC_ELF_SECTION_NAME ".obfsc"
#define OBF_SC_ELF_SECTION_PREFIX ".obfsc."

#if defined(__cplusplus)
static_assert(OBF_SC_OFF_RESERVED1 + OBF_SC_RESERVED1_SIZE == OBF_SC_RECORD_SIZE,
              "self-checksum v1 record layout must remain exactly 96 bytes");
#endif
