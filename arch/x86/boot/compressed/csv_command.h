/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _CSV_COMMAND_H_
#define _CSV_COMMAND_H_

#ifdef CONFIG_HYGON_CSV

void csv_update_page_attr(unsigned long address, pteval_t set, pteval_t clr);

#else /* !CONFIG_HYGON_CSV */

static inline void csv_update_page_attr(unsigned long address,
					pteval_t set, pteval_t clr) { }

#endif /* CONFIG_HYGON_CSV */

#endif
