/*
 * venus_ir_wo - Realtek Venus IR Write-Only device
 *
 * Copyright (c) 2011, Pete B. <xtreamerdev@gmail.com>
 *
 * Based on venus_ir_new.c (c) 2010 Gouzhuang:
 *  http://www.cnitblog.com/gouzhuang/archive/2010/05/14/remote_control.html
 * Based on venus_ir_new2.c (c) 2010 Sekator500:
 *  http://www.moservices.org/forum/viewtopic.php?f=12&t=179&start=10#p6580
 * Based on venus_ir.c (c) 2009-2010 Realtek
 *  http://forum.xtreamer.net/mediawiki-1.15.1/index.php/Xtreamer_Source-code#Linux_Kernel
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#define VENUS_IR_WO_MAJOR		234
#define VENUS_IR_WO_DEVICE_NUM		2
#define VENUS_IR_WO_MINOR_RP		52
#define VENUS_IR_WO_DEVICE_FILE		"venus_irrp_wo"

#define VENUS_IR_WO_IOC_MAGIC		'r'
#define VENUS_IR_WO_IOC_TEST		_IOW(VENUS_IR_WO_IOC_MAGIC, 1, int)
#define VENUS_IR_WO_IOC_MAXNR		1

/* Use our own dbg macro */
#undef dbg
#define dbg(format, arg...) do { if (debug) printk(KERN_INFO "%s: " format , __FUNCTION__ , ## arg); } while (0)
