#include <xsmartnic_ebpf_api_mc.h>

int handler(struct xnice_plugin_init_md *ctx)
{
  xnice_host_set_routing(ctx, XSN_SCOPE_HOST, 0x10, 0);
  xnice_mac_set_routing(ctx, -1, -1, 0x20);
  return 0;
}
