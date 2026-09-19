/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_DM_ROOTCRYPT_H
#define _LINUX_DM_ROOTCRYPT_H

#include <linux/init.h>

#ifdef CONFIG_DM_CRYPT_ROOT
int __init dm_crypt_root_setup(const char *root);
#else
static inline int dm_crypt_root_setup(const char *root)
{
	return 0;
}
#endif

#endif /* _LINUX_DM_ROOTCRYPT_H */
