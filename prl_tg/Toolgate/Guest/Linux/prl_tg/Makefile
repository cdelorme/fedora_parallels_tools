######################################################
# Copyright (C) 2005-2008 Parallels Software Inc.    #
# All Rights Reserved.                               #
# http://www.parallels.com                           #
######################################################
#
# To make driver for current kernel:
#
#        make
#
# To make driver for other kernel:
#
#        make KERNEL_DIR=<PATH_TO_KERNEL>
#

KVER ?= $(shell uname -r)
KERNEL_DIR ?= /lib/modules/$(KVER)/build

DRIVER := prl_tg
DRIVER_DIR ?= $(PWD)

export DRIVER_DIR

EXTRA_CFLAGS	+=  -I$(DRIVER_DIR)
EXTRA_CFLAGS	+= -I$(DRIVER_DIR)/../../../../

# Get version from version.h in kernel source directory
ifeq "$(wildcard $(KERNEL_DIR)/include/linux/version.h)" ""
	VERSION_H_PATH ?= $(KERNEL_DIR)/include/generated/uapi/linux/version.h
else
	VERSION_H_PATH ?= $(KERNEL_DIR)/include/linux/version.h
endif

VERSION_CODE := $(shell awk '/\#define[ \t]+LINUX_VERSION_CODE[ \t]\
	*/ { print $$3 }' $(VERSION_H_PATH) | tail -n 1)

ifeq ($(shell if [ $(VERSION_CODE) -ge 132608 ]; then echo y; fi),y)
LINUX_VER := 26
else
ifeq ($(shell if [ $(VERSION_CODE) -ge 132096 -a $(VERSION_CODE) -le 132351 ]; \
	 then echo y; fi),y)
LINUX_VER := 24
else
  $(error Unsupported kernel version $(VERSION_CODE) in $(KERNEL_DIR))
endif
endif

ifeq "$(LINUX_VER)" "26"
include $(DRIVER_DIR)/Makefile.v26
else
ifeq "$(LINUX_VER)" "24"
export DRIVER_DIR
include $(DRIVER_DIR)/Makefile.v24
endif
endif
