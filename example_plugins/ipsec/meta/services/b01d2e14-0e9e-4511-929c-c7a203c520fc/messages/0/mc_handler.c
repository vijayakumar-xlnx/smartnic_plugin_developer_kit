#define PCM_IPSEC_CMD_INFO

#include <stdint.h>
#include <stdlib.h>
#include <xsmartnic_ebpf_api_mc.h>
#include "../../../../ipsec_demo.h"

int handler(struct xnice_plugin_mcmsg_md *ctx)
{
	struct efx_ipsec_info *resp = (void *)(long)ctx->payload;
	resp->ver_major = PCM_MC_HANDLER_MAJOR;
	resp->ver_minor = PCM_MC_HANDLER_MINOR;
	resp->modes = PCM_IPSEC_CAP_MODE_TUNNEL |
		PCM_IPSEC_CAP_MODE_TRANSPORT;
	resp->num_cam_entries = PCM_MC_MAX_CAM_ENTRIES;

	return 0;
}
