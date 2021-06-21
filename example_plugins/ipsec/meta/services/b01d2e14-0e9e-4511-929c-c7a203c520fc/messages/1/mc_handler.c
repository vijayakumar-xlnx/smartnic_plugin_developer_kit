#define PCM_IPSEC_CMD_READ_CIPHERS

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <xsmartnic_ebpf_api_mc.h>
#include "../../../../ipsec_demo.h"


static const struct efx_ipsec_cipher ciphers[2] = {
	{"rfc4106(gcm(aes))", 1, 0, 1, 1},
	{"rfc4543(gcm(aes))", 2, 0, 1, 1}
};

int handler(struct xnice_plugin_mcmsg_md *ctx)
{
	unsigned char *resp = (void*)(long)ctx->payload;
	memcpy(resp, ciphers, 136);
	return 0;
}
