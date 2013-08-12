/*
 *	prltg_call.h
 *	Parallels Toolgate driver kernelspace interface
 *	Copyright (c) 2008 Parallels Inc. All Rights Reserved.
 */

#include "Toolgate/Guest/Linux/Interfaces/prltg.h"
extern int call_tg_sync(struct pci_dev *, TG_REQ_DESC *);
