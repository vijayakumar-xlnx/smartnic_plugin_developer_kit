#define PCM_IPSEC_CMD_CAM_TABLE_OP

#include <stdint.h>
#include <stdlib.h>
#include <error.h>
#include <xsmartnic_ebpf_api_mc.h>
#include "../../../../ipsec_demo.h"

extern struct xnice_cam tx_sadb;
extern struct xnice_cam rx_sadb;

int handler(struct xnice_plugin_mcmsg_md *ctx)
{
	struct efx_ipsec_sadb_op *attr = (void *)(long)ctx->payload;
	struct xnice_cam *cam;
	struct efx_ipsec_sa_attr *sa_attr;

	sa_attr = &attr->sa;
    switch (attr->table_dir) {
        case PCM_IPSEC_CMD_CAM_TABLE_OP_IN_SADBSEL_CAMIDX_TX:
            cam = &tx_sadb;
            break;
        case PCM_IPSEC_CMD_CAM_TABLE_OP_IN_SADBSEL_CAMIDX_RX:
            cam = &rx_sadb;
            break;
        default:
            //return -EINVAL;
            return -22;
    }

    switch (attr->op) {
        case PCM_IPSEC_CMD_CAM_TABLE_OP_IN_OPCODE_ADD:
			return xnice_cam_insert(cam, &sa_attr->sa_key,
					NULL, 0, &sa_attr->sa_val);
        case PCM_IPSEC_CMD_CAM_TABLE_OP_IN_OPCODE_UPD:
			return xnice_cam_update(cam, &sa_attr->sa_key,
					NULL, &sa_attr->sa_val);
        case PCM_IPSEC_CMD_CAM_TABLE_OP_IN_OPCODE_DEL:
            return xnice_cam_delete(cam, &sa_attr->sa_key, NULL);
        default:
            return -22;
    }

    return -22;
}
