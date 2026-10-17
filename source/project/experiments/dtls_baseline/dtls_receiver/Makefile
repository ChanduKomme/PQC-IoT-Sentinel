PROJECT_NAME := dtls_receiver
PROJECT_PATH := $(abspath .)
PROJECT_BOARD := evb
export PROJECT_PATH PROJECT_BOARD

-include ./proj_config.mk

PROJECT_FLAGS := -DWITH_LWIP
PROJECT_FLAGS += $(DTLS_EXTRA_CFLAGS)
CFLAGS   += $(PROJECT_FLAGS)
CPPFLAGS += $(PROJECT_FLAGS)
CXXFLAGS += $(PROJECT_FLAGS)

ifeq ($(origin BL60X_SDK_PATH), undefined)
$(error ****** Please set BL60X_SDK_PATH ******)
endif

COMPONENTS_NETWORK := dns_server lwip lwip_dhcpd
COMPONENTS_BLSYS := bltime blfdt blmtd bloop looprt loopset
COMPONENTS_VFS := romfs

INCLUDE_COMPONENTS += freertos bl602 bl602_std bl602_wifi bl602_wifidrv
INCLUDE_COMPONENTS += hal_drv vfs yloop utils cli blog blog_testc
INCLUDE_COMPONENTS += easyflash4 mbedtls-bl602 etl
INCLUDE_COMPONENTS += $(COMPONENTS_NETWORK) $(COMPONENTS_BLSYS) $(COMPONENTS_VFS)
INCLUDE_COMPONENTS += $(PROJECT_NAME)

include $(BL60X_SDK_PATH)/make_scripts_riscv/project.mk
