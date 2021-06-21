# SPDX-License-Identifier: Apache-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2021 Xilinx, Inc.

META_SCRIPT := common/scripts/xnice-metadata-compile.py
EBPF_HEADER := common/include/xsmartnic_ebpf_api_mc.h
META_CFLAGS := -Wextra -I$(dir $(EBPF_HEADER))

ifeq ($(wildcard $(PLUGIN)), )
  $(error Must set PLUGIN to the path of the plugin to be built)
endif
PLUGIN_NAME := $(notdir $(PLUGIN))
BUILD_DIR ?= $(PLUGIN)/build
META_OUT ?= $(BUILD_DIR)/meta.dtb

# There are two stages to building an xclbin. First we compile a raw xclbin,
# and then we use xclbinutil to embed metadata into it.
XCLBIN_RAW_OUT ?= $(BUILD_DIR)/$(PLUGIN_NAME).raw.xclbin
XCLBIN_OUT ?= $(BUILD_DIR)/$(PLUGIN_NAME).xclbin


.PHONY: all clean meta host xclbin

all: meta host

clean:
	rm -rf $(BUILD_DIR)

meta: $(META_OUT)
xclbin: $(XCLBIN_OUT)

# xnice-metadata-compile.py scans entire subdirectories looking for things
# and its behaviour changes depending on whether it finds them or not, so
# it's correct to make the .dtb depend on every file and every subdirectory
# in its source tree:
$(META_OUT): $(shell find $(PLUGIN)/meta) $(META_SCRIPT) $(EBPF_HEADER)
	@mkdir -p $(@D)
	CFLAGS="$(META_CFLAGS)" $(META_SCRIPT) $(PLUGIN)/meta > $@ || (rm $@ && false)

host:
	@[ -f "${PLUGIN}/host/Makefile" ] || (echo "Plugin does not have a host Makefile" && false)
	@mkdir -p $(BUILD_DIR)
-include $(PLUGIN)/host/Makefile

$(XCLBIN_RAW_OUT):
	@mkdir -p $(@D)
	make -C $(PLUGIN) XCLBIN=$(abspath $@)

$(XCLBIN_OUT): $(META_OUT) $(XCLBIN_RAW_OUT)
	xclbinutil --input $(XCLBIN_RAW_OUT) --add-section USER_METADATA:RAW:$(META_OUT) --output $@
