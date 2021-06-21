#ifndef INCLUDED_XSMARTNIC_IPSEC_H_
#define INCLUDED_XSMARTNIC_IPSEC_H_

/* UUID assigned to IPSec plugin */
static const uint8_t XSN_IPSEC_PLUGIN[] = {
    0xB0, 0x1D, 0x2E, 0x14, 0xE, 0x9E, 0x45, 0x11,
    0x92, 0x9C, 0xC7, 0xA2, 0x3, 0xC5, 0x20, 0xFC
};

/**********************************************************/
/************ Supported list of PCM Commands **************/
/**********************************************************/
#ifdef PCM_IPSEC_CMD_INFO
#undef PCM_IPSEC_CMD_INFO
/* PCM command to read version and capability information */
#define PCM_IPSEC_CMD_INFO 0
#define     PCM_IPSEC_CMD_INFO_IN_LEN PCM_CMD_IN_LEN 0
#define     PCM_IPSEC_CMD_INFO_OUT_LEN 6

/* Response only */
struct efx_ipsec_info {
    uint8_t ver_major;
#define PCM_MC_HANDLER_MAJOR 0
    uint8_t ver_minor;
#define PCM_MC_HANDLER_MINOR 4
    uint16_t modes;
#define PCM_IPSEC_CAP_MODE_TUNNEL    (1 << 0)
#define PCM_IPSEC_CAP_MODE_TRANSPORT (1 << 1)
    uint16_t num_cam_entries;
#define PCM_MC_MAX_CAM_ENTRIES 8192
} __attribute__((packed));
#endif

#ifdef PCM_IPSEC_CMD_READ_CIPHERS
#undef PCM_IPSEC_CMD_READ_CIPHERS
/* PCM command to read supported Ciphers */
#define PCM_IPSEC_CMD_READ_CIPHERS 1
#define     PCM_IPSEC_CMD_READ_CIPHERS_IN_LEN PCM_CMD_IN_LEN 0
#define     PCM_IPSEC_CMD_READ_CIPHERS_OUT_LEN 136

/* Response only */
struct efx_ipsec_cipher {
    char name[64];
    uint8_t id;
#define PCM_IPSEC_CIPHER_ENCR_AES_GCM 1
#define PCM_IPSEC_CIPHER_NULL_AUTH_AES_GCM 2
    uint8_t hw_ver;
#define PCM_IPSEC_READ_CIPHERS_HW_VERSION 0
    uint8_t keylen;
#define PCM_IPSEC_READ_CIPHERS_KEY_LEN 1 /* 128 bits */
    uint8_t icvlen;
#define PCM_IPSEC_READ_CIPHERS_ICV_LEN 1 /* 128 bits */
} __attribute__((packed));
#endif

/*
 * PCM command to Update HW SADB
 * All the values in the IN fileds are expected to be Bigendian
 *   Exception tothis rule are sa_id, un_cookie and opcode
 */
#ifdef PCM_IPSEC_CMD_CAM_TABLE_OP
#undef PCM_IPSEC_CMD_CAM_TABLE_OP
#define PCM_IPSEC_CMD_CAM_TABLE_OP 2
#define     PCM_IPSEC_CMD_CAM_TABLE_OP_IN_LEN 120

/* Request - BE only*/
struct sa_key {
    uint8_t dst_ip[16];
    uint8_t src_ip[16];
    uint32_t spi;
} __attribute__((packed));

/* Request  - BE format only except cipher_flags */
struct sa_val {
	struct cipher_options {
		uint8_t rsvd0;
		uint8_t rsvd1;
		uint8_t rsvd2;
		uint8_t keylen:2;
#define PCM_IPSEC_CIPHER_PARAMS_SPI_KEYLEN128 0
		uint8_t icvlen:2;
#define PCM_IPSEC_CIPHER_PARAMS_SPI_ICVLEN128 0
		uint8_t esn:1;
#define PCM_IPSEC_CIPHER_PARAMS_ESN_ENABLE 1
#define PCM_IPSEC_CIPHER_PARAMS_ESN_DISABLE 0
	} cipher_flags;
    uint32_t iv_salt;
    uint8_t hwivgen;
#define PCM_IPSEC_NO_HW_IV_GEN 0
#define PCM_IPSEC_DPDK_HW_IV_GEN 1
#define PCM_IPSEC_LINUX_HW_IV_GEN 2
    uint16_t um_cookie;
    uint8_t key[64];
    uint8_t cipher_id;
#define PCM_IPSEC_CIPHER_ENCR_AES_GCM 1
#define PCM_IPSEC_CIPHER_NULL_AUTH_AES_GCM 2
	uint32_t esn;
} __attribute__((packed));

/* Request */
struct efx_ipsec_sa_attr {
    struct sa_key sa_key;
    struct sa_val sa_val;
} __attribute__((packed));

/* Request */
struct efx_ipsec_sadb_op {
    uint8_t op;
#define PCM_IPSEC_CMD_CAM_TABLE_OP_IN_OPCODE_DEL 0
#define PCM_IPSEC_CMD_CAM_TABLE_OP_IN_OPCODE_ADD 1
#define PCM_IPSEC_CMD_CAM_TABLE_OP_IN_OPCODE_UPD 2

    uint8_t table_dir;
#define PCM_IPSEC_CMD_CAM_TABLE_OP_IN_SADBSEL_CAMIDX_TX 0
#define PCM_IPSEC_CMD_CAM_TABLE_OP_IN_SADBSEL_CAMIDX_RX 1

    uint16_t sadb_id;
    struct efx_ipsec_sa_attr sa;
} __attribute__((packed));
#endif

/* PCM command to read Plugin counters */
#ifdef PCM_IPSEC_CMD_ESP_STATS
#undef PCM_IPSEC_CMD_ESP_STATS
#define PCM_IPSEC_CMD_ESP_STATS 3
#define     PCM_IPSEC_CMD_ESP_STAT_IN_LEN 1
#define     PCM_IPSEC_CMD_ESP_STAT_OUT_LEN 32

struct efx_ipsec_esp_stats {
    uint8_t cipher_id;
    uint64_t protected_bytes;
    uint64_t encrypted_bytes;
    uint64_t validated_bytes;
    uint64_t decrypted_bytes;
} __attribute__((packed));
#endif

#ifdef PCM_IPSEC_CMD_CAM_RESET
#define     PCM_IPSEC_CMD_CAM_RESET_IN_LEN 4
#define     PCM_IPSEC_CMD_ESP_STAT_OUT_LEN 0
#define PCM_IPSEC_CMD_CAM_TABLE_OP_IN_SADBSEL_CAMIDX_TX 0
#define PCM_IPSEC_CMD_CAM_TABLE_OP_IN_SADBSEL_CAMIDX_RX 1
#endif

#endif
