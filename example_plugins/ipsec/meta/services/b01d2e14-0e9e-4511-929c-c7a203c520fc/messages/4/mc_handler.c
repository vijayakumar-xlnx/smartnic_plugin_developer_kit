#define PCM_IPSEC_CMD_CAM_RESET

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <xsmartnic_ebpf_api_mc.h>
#include "../../../../ipsec_demo.h"

extern struct xnice_cam tx_sadb;
extern struct xnice_cam rx_sadb;

int handler(struct xnice_plugin_mcmsg_md *ctx)
{
	uint32_t *cam_table = (void *)(long)ctx->payload;
	struct xnice_cam *cam;

	switch (*cam_table) {
		case PCM_IPSEC_CMD_CAM_TABLE_OP_IN_SADBSEL_CAMIDX_TX:
			cam = &tx_sadb;
			break;
		case PCM_IPSEC_CMD_CAM_TABLE_OP_IN_SADBSEL_CAMIDX_RX:
			cam = &rx_sadb;
			break;
		default:
			return -22;
	}

	return xnice_cam_reset(cam);
}
