######################################################
# Copyright (C) 2005-2009 Parallels Software Inc.    #
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

modules clean:
	make -C ${KERNEL_DIR} M=${PWD} $@
obj-m = prl_fs_freeze.o
