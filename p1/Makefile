# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS := xdp_pass_kern
XDP_TARGETS += xdp_drop_kern
XDP_TARGETS += xdp_redirect_kern
XDP_TARGETS += xdp_tx_kern

LLC ?= llc
CLANG ?= clang
CC := gcc

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/

include $(COMMON_DIR)/common.mk
COMMON_OBJS := $(COMMON_DIR)/common_params.o

clean:
	rm *.o *.ll
