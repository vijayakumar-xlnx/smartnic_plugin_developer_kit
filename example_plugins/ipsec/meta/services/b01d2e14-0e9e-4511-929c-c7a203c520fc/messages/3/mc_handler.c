#define PCM_IPSEC_CMD_ESP_STATS

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <xsmartnic_ebpf_api_mc.h>
#include "../../../../ipsec_demo.h"

#define BASE_CIPHER_ENCR_AES_GCM 0x600000
#define BASE_CIPHER_NULL_AUTH_AES_GCM 0x400000

#define CIPHER_ENCR_AES_GCM 1
#define CIPHER_NULL_AUTH_AES_GCM 2

int handler(struct xnice_plugin_mcmsg_md *ctx)
{
	struct efx_ipsec_esp_stats *resp = (void *)(long)ctx->payload;
    uint64_t reg;
    
    if (resp->cipher_id == CIPHER_ENCR_AES_GCM)
        reg = BASE_CIPHER_ENCR_AES_GCM; 
    else if (resp->cipher_id == CIPHER_NULL_AUTH_AES_GCM)
        reg = BASE_CIPHER_NULL_AUTH_AES_GCM;
    else
        return -EINVAL;
#if 0
    resp->protected_bytes = xnice_readl(reg);
    resp->encrypted_bytes = xnice_readl(reg + 4);
    resp->validated_bytes = xnice_readl(reg + 8;
    resp->decrypted_bytes = xnice_readl(reg + 12);
#endif
	return 0;
}
