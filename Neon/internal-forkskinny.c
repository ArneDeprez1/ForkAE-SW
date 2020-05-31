/*
 * Copyright (C) 2020 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "internal-forkskinny.h"
#include "internal-skinnyutil.h"

/**
 * \brief 7-bit round constants for all ForkSkinny block ciphers.
 */
static unsigned char const RC[87] = {0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7e, 0x7d, 0x7b, 0x77, 0x6f, 0x5f, 0x3e, 0x7c, 0x79, 0x73, 0x67, 0x4f, 0x1e, 0x3d, 0x7a, 0x75, 0x6b, 0x57, 0x2e, 0x5c, 0x38, 0x70, 0x61, 0x43, 0x06, 0x0d, 0x1b, 0x37, 0x6e, 0x5d, 0x3a, 0x74, 0x69, 0x53, 0x26, 0x4c, 0x18, 0x31, 0x62, 0x45, 0x0a, 0x15, 0x2b, 0x56, 0x2c, 0x58, 0x30, 0x60, 0x41, 0x02, 0x05, 0x0b, 0x17, 0x2f, 0x5e, 0x3c, 0x78, 0x71, 0x63, 0x47, 0x0e, 0x1d, 0x3b, 0x76, 0x6d, 0x5b,0x36, 0x6c, 0x59, 0x32, 0x64, 0x49, 0x12, 0x25, 0x4a, 0x14, 0x29, 0x52, 0x24, 0x48, 0x10};

static const uint32_t T0[256] = {0x65006565, 0x4c004c4c, 0x6a006a6a, 0x42004242, 0x4b004b4b, 0x63006363, 0x43004343, 0x6b006b6b, 0x55005555, 0x75007575, 0x5a005a5a, 0x7a007a7a, 0x53005353, 0x73007373, 0x5b005b5b, 0x7b007b7b, 0x35003535, 0x8c008c8c, 0x3a003a3a, 0x81008181, 0x89008989, 0x33003333, 0x80008080, 0x3b003b3b, 0x95009595, 0x25002525, 0x98009898, 0x2a002a2a, 0x90009090, 0x23002323, 0x99009999, 0x2b002b2b, 0xe500e5e5, 0xcc00cccc, 0xe800e8e8, 0xc100c1c1, 0xc900c9c9, 0xe000e0e0, 0xc000c0c0, 0xe900e9e9, 0xd500d5d5, 0xf500f5f5, 0xd800d8d8, 0xf800f8f8, 0xd000d0d0, 0xf000f0f0, 0xd900d9d9, 0xf900f9f9, 0xa500a5a5, 0x1c001c1c, 0xa800a8a8, 0x12001212, 0x1b001b1b, 0xa000a0a0, 0x13001313, 0xa900a9a9, 0x05000505, 0xb500b5b5, 0x0a000a0a, 0xb800b8b8, 0x03000303, 0xb000b0b0, 0x0b000b0b, 0xb900b9b9, 0x32003232, 0x88008888, 0x3c003c3c, 0x85008585, 0x8d008d8d, 0x34003434, 0x84008484, 0x3d003d3d, 0x91009191, 0x22002222, 0x9c009c9c, 0x2c002c2c, 0x94009494, 0x24002424, 0x9d009d9d, 0x2d002d2d, 0x62006262, 0x4a004a4a, 0x6c006c6c, 0x45004545, 0x4d004d4d, 0x64006464, 0x44004444, 0x6d006d6d, 0x52005252, 0x72007272, 0x5c005c5c, 0x7c007c7c, 0x54005454, 0x74007474, 0x5d005d5d, 0x7d007d7d, 0xa100a1a1, 0x1a001a1a, 0xac00acac, 0x15001515, 0x1d001d1d, 0xa400a4a4, 0x14001414, 0xad00adad, 0x02000202, 0xb100b1b1, 0x0c000c0c, 0xbc00bcbc, 0x04000404, 0xb400b4b4, 0x0d000d0d, 0xbd00bdbd, 0xe100e1e1, 0xc800c8c8, 0xec00ecec, 0xc500c5c5, 0xcd00cdcd, 0xe400e4e4, 0xc400c4c4, 0xed00eded, 0xd100d1d1, 0xf100f1f1, 0xdc00dcdc, 0xfc00fcfc, 0xd400d4d4, 0xf400f4f4, 0xdd00dddd, 0xfd00fdfd, 0x36003636, 0x8e008e8e, 0x38003838, 0x82008282, 0x8b008b8b, 0x30003030, 0x83008383, 0x39003939, 0x96009696, 0x26002626, 0x9a009a9a, 0x28002828, 0x93009393, 0x20002020, 0x9b009b9b, 0x29002929, 0x66006666, 0x4e004e4e, 0x68006868, 0x41004141, 0x49004949, 0x60006060, 0x40004040, 0x69006969, 0x56005656, 0x76007676, 0x58005858, 0x78007878, 0x50005050, 0x70007070, 0x59005959, 0x79007979, 0xa600a6a6, 0x1e001e1e, 0xaa00aaaa, 0x11001111, 0x19001919, 0xa300a3a3, 0x10001010, 0xab00abab, 0x06000606, 0xb600b6b6, 0x08000808, 0xba00baba, 0x00000000, 0xb300b3b3, 0x09000909, 0xbb00bbbb, 0xe600e6e6, 0xce00cece, 0xea00eaea, 0xc200c2c2, 0xcb00cbcb, 0xe300e3e3, 0xc300c3c3, 0xeb00ebeb, 0xd600d6d6, 0xf600f6f6, 0xda00dada, 0xfa00fafa, 0xd300d3d3, 0xf300f3f3, 0xdb00dbdb, 0xfb00fbfb, 0x31003131, 0x8a008a8a, 0x3e003e3e, 0x86008686, 0x8f008f8f, 0x37003737, 0x87008787, 0x3f003f3f, 0x92009292, 0x21002121, 0x9e009e9e, 0x2e002e2e, 0x97009797, 0x27002727, 0x9f009f9f, 0x2f002f2f, 0x61006161, 0x48004848, 0x6e006e6e, 0x46004646, 0x4f004f4f, 0x67006767, 0x47004747, 0x6f006f6f, 0x51005151, 0x71007171, 0x5e005e5e, 0x7e007e7e, 0x57005757, 0x77007777, 0x5f005f5f, 0x7f007f7f, 0xa200a2a2, 0x18001818, 0xae00aeae, 0x16001616, 0x1f001f1f, 0xa700a7a7, 0x17001717, 0xaf00afaf, 0x01000101, 0xb200b2b2, 0x0e000e0e, 0xbe00bebe, 0x07000707, 0xb700b7b7, 0x0f000f0f, 0xbf00bfbf, 0xe200e2e2, 0xca00caca, 0xee00eeee, 0xc600c6c6, 0xcf00cfcf, 0xe700e7e7, 0xc700c7c7, 0xef00efef, 0xd200d2d2, 0xf200f2f2, 0xde00dede, 0xfe00fefe, 0xd700d7d7, 0xf700f7f7, 0xdf00dfdf, 0xff00ffff};
static const uint32_t T1[256] = {0x00650000, 0x004c0000, 0x006a0000, 0x00420000, 0x004b0000, 0x00630000, 0x00430000, 0x006b0000, 0x00550000, 0x00750000, 0x005a0000, 0x007a0000, 0x00530000, 0x00730000, 0x005b0000, 0x007b0000, 0x00350000, 0x008c0000, 0x003a0000, 0x00810000, 0x00890000, 0x00330000, 0x00800000, 0x003b0000, 0x00950000, 0x00250000, 0x00980000, 0x002a0000, 0x00900000, 0x00230000, 0x00990000, 0x002b0000, 0x00e50000, 0x00cc0000, 0x00e80000, 0x00c10000, 0x00c90000, 0x00e00000, 0x00c00000, 0x00e90000, 0x00d50000, 0x00f50000, 0x00d80000, 0x00f80000, 0x00d00000, 0x00f00000, 0x00d90000, 0x00f90000, 0x00a50000, 0x001c0000, 0x00a80000, 0x00120000, 0x001b0000, 0x00a00000, 0x00130000, 0x00a90000, 0x00050000, 0x00b50000, 0x000a0000, 0x00b80000, 0x00030000, 0x00b00000, 0x000b0000, 0x00b90000, 0x00320000, 0x00880000, 0x003c0000, 0x00850000, 0x008d0000, 0x00340000, 0x00840000, 0x003d0000, 0x00910000, 0x00220000, 0x009c0000, 0x002c0000, 0x00940000, 0x00240000, 0x009d0000, 0x002d0000, 0x00620000, 0x004a0000, 0x006c0000, 0x00450000, 0x004d0000, 0x00640000, 0x00440000, 0x006d0000, 0x00520000, 0x00720000, 0x005c0000, 0x007c0000, 0x00540000, 0x00740000, 0x005d0000, 0x007d0000, 0x00a10000, 0x001a0000, 0x00ac0000, 0x00150000, 0x001d0000, 0x00a40000, 0x00140000, 0x00ad0000, 0x00020000, 0x00b10000, 0x000c0000, 0x00bc0000, 0x00040000, 0x00b40000, 0x000d0000, 0x00bd0000, 0x00e10000, 0x00c80000, 0x00ec0000, 0x00c50000, 0x00cd0000, 0x00e40000, 0x00c40000, 0x00ed0000, 0x00d10000, 0x00f10000, 0x00dc0000, 0x00fc0000, 0x00d40000, 0x00f40000, 0x00dd0000, 0x00fd0000, 0x00360000, 0x008e0000, 0x00380000, 0x00820000, 0x008b0000, 0x00300000, 0x00830000, 0x00390000, 0x00960000, 0x00260000, 0x009a0000, 0x00280000, 0x00930000, 0x00200000, 0x009b0000, 0x00290000, 0x00660000, 0x004e0000, 0x00680000, 0x00410000, 0x00490000, 0x00600000, 0x00400000, 0x00690000, 0x00560000, 0x00760000, 0x00580000, 0x00780000, 0x00500000, 0x00700000, 0x00590000, 0x00790000, 0x00a60000, 0x001e0000, 0x00aa0000, 0x00110000, 0x00190000, 0x00a30000, 0x00100000, 0x00ab0000, 0x00060000, 0x00b60000, 0x00080000, 0x00ba0000, 0x00000000, 0x00b30000, 0x00090000, 0x00bb0000, 0x00e60000, 0x00ce0000, 0x00ea0000, 0x00c20000, 0x00cb0000, 0x00e30000, 0x00c30000, 0x00eb0000, 0x00d60000, 0x00f60000, 0x00da0000, 0x00fa0000, 0x00d30000, 0x00f30000, 0x00db0000, 0x00fb0000, 0x00310000, 0x008a0000, 0x003e0000, 0x00860000, 0x008f0000, 0x00370000, 0x00870000, 0x003f0000, 0x00920000, 0x00210000, 0x009e0000, 0x002e0000, 0x00970000, 0x00270000, 0x009f0000, 0x002f0000, 0x00610000, 0x00480000, 0x006e0000, 0x00460000, 0x004f0000, 0x00670000, 0x00470000, 0x006f0000, 0x00510000, 0x00710000, 0x005e0000, 0x007e0000, 0x00570000, 0x00770000, 0x005f0000, 0x007f0000, 0x00a20000, 0x00180000, 0x00ae0000, 0x00160000, 0x001f0000, 0x00a70000, 0x00170000, 0x00af0000, 0x00010000, 0x00b20000, 0x000e0000, 0x00be0000, 0x00070000, 0x00b70000, 0x000f0000, 0x00bf0000, 0x00e20000, 0x00ca0000, 0x00ee0000, 0x00c60000, 0x00cf0000, 0x00e70000, 0x00c70000, 0x00ef0000, 0x00d20000, 0x00f20000, 0x00de0000, 0x00fe0000, 0x00d70000, 0x00f70000, 0x00df0000, 0x00ff0000};
static const uint32_t T2[256] = {0x65650065, 0x4c4c004c, 0x6a6a006a, 0x42420042, 0x4b4b004b, 0x63630063, 0x43430043, 0x6b6b006b, 0x55550055, 0x75750075, 0x5a5a005a, 0x7a7a007a, 0x53530053, 0x73730073, 0x5b5b005b, 0x7b7b007b, 0x35350035, 0x8c8c008c, 0x3a3a003a, 0x81810081, 0x89890089, 0x33330033, 0x80800080, 0x3b3b003b, 0x95950095, 0x25250025, 0x98980098, 0x2a2a002a, 0x90900090, 0x23230023, 0x99990099, 0x2b2b002b, 0xe5e500e5, 0xcccc00cc, 0xe8e800e8, 0xc1c100c1, 0xc9c900c9, 0xe0e000e0, 0xc0c000c0, 0xe9e900e9, 0xd5d500d5, 0xf5f500f5, 0xd8d800d8, 0xf8f800f8, 0xd0d000d0, 0xf0f000f0, 0xd9d900d9, 0xf9f900f9, 0xa5a500a5, 0x1c1c001c, 0xa8a800a8, 0x12120012, 0x1b1b001b, 0xa0a000a0, 0x13130013, 0xa9a900a9, 0x05050005, 0xb5b500b5, 0x0a0a000a, 0xb8b800b8, 0x03030003, 0xb0b000b0, 0x0b0b000b, 0xb9b900b9, 0x32320032, 0x88880088, 0x3c3c003c, 0x85850085, 0x8d8d008d, 0x34340034, 0x84840084, 0x3d3d003d, 0x91910091, 0x22220022, 0x9c9c009c, 0x2c2c002c, 0x94940094, 0x24240024, 0x9d9d009d, 0x2d2d002d, 0x62620062, 0x4a4a004a, 0x6c6c006c, 0x45450045, 0x4d4d004d, 0x64640064, 0x44440044, 0x6d6d006d, 0x52520052, 0x72720072, 0x5c5c005c, 0x7c7c007c, 0x54540054, 0x74740074, 0x5d5d005d, 0x7d7d007d, 0xa1a100a1, 0x1a1a001a, 0xacac00ac, 0x15150015, 0x1d1d001d, 0xa4a400a4, 0x14140014, 0xadad00ad, 0x02020002, 0xb1b100b1, 0x0c0c000c, 0xbcbc00bc, 0x04040004, 0xb4b400b4, 0x0d0d000d, 0xbdbd00bd, 0xe1e100e1, 0xc8c800c8, 0xecec00ec, 0xc5c500c5, 0xcdcd00cd, 0xe4e400e4, 0xc4c400c4, 0xeded00ed, 0xd1d100d1, 0xf1f100f1, 0xdcdc00dc, 0xfcfc00fc, 0xd4d400d4, 0xf4f400f4, 0xdddd00dd, 0xfdfd00fd, 0x36360036, 0x8e8e008e, 0x38380038, 0x82820082, 0x8b8b008b, 0x30300030, 0x83830083, 0x39390039, 0x96960096, 0x26260026, 0x9a9a009a, 0x28280028, 0x93930093, 0x20200020, 0x9b9b009b, 0x29290029, 0x66660066, 0x4e4e004e, 0x68680068, 0x41410041, 0x49490049, 0x60600060, 0x40400040, 0x69690069, 0x56560056, 0x76760076, 0x58580058, 0x78780078, 0x50500050, 0x70700070, 0x59590059, 0x79790079, 0xa6a600a6, 0x1e1e001e, 0xaaaa00aa, 0x11110011, 0x19190019, 0xa3a300a3, 0x10100010, 0xabab00ab, 0x06060006, 0xb6b600b6, 0x08080008, 0xbaba00ba, 0x00000000, 0xb3b300b3, 0x09090009, 0xbbbb00bb, 0xe6e600e6, 0xcece00ce, 0xeaea00ea, 0xc2c200c2, 0xcbcb00cb, 0xe3e300e3, 0xc3c300c3, 0xebeb00eb, 0xd6d600d6, 0xf6f600f6, 0xdada00da, 0xfafa00fa, 0xd3d300d3, 0xf3f300f3, 0xdbdb00db, 0xfbfb00fb, 0x31310031, 0x8a8a008a, 0x3e3e003e, 0x86860086, 0x8f8f008f, 0x37370037, 0x87870087, 0x3f3f003f, 0x92920092, 0x21210021, 0x9e9e009e, 0x2e2e002e, 0x97970097, 0x27270027, 0x9f9f009f, 0x2f2f002f, 0x61610061, 0x48480048, 0x6e6e006e, 0x46460046, 0x4f4f004f, 0x67670067, 0x47470047, 0x6f6f006f, 0x51510051, 0x71710071, 0x5e5e005e, 0x7e7e007e, 0x57570057, 0x77770077, 0x5f5f005f, 0x7f7f007f, 0xa2a200a2, 0x18180018, 0xaeae00ae, 0x16160016, 0x1f1f001f, 0xa7a700a7, 0x17170017, 0xafaf00af, 0x01010001, 0xb2b200b2, 0x0e0e000e, 0xbebe00be, 0x07070007, 0xb7b700b7, 0x0f0f000f, 0xbfbf00bf, 0xe2e200e2, 0xcaca00ca, 0xeeee00ee, 0xc6c600c6, 0xcfcf00cf, 0xe7e700e7, 0xc7c700c7, 0xefef00ef, 0xd2d200d2, 0xf2f200f2, 0xdede00de, 0xfefe00fe, 0xd7d700d7, 0xf7f700f7, 0xdfdf00df, 0xffff00ff};
static const uint32_t T3[256] = {0x00000065, 0x0000004c, 0x0000006a, 0x00000042, 0x0000004b, 0x00000063, 0x00000043, 0x0000006b, 0x00000055, 0x00000075, 0x0000005a, 0x0000007a, 0x00000053, 0x00000073, 0x0000005b, 0x0000007b, 0x00000035, 0x0000008c, 0x0000003a, 0x00000081, 0x00000089, 0x00000033, 0x00000080, 0x0000003b, 0x00000095, 0x00000025, 0x00000098, 0x0000002a, 0x00000090, 0x00000023, 0x00000099, 0x0000002b, 0x000000e5, 0x000000cc, 0x000000e8, 0x000000c1, 0x000000c9, 0x000000e0, 0x000000c0, 0x000000e9, 0x000000d5, 0x000000f5, 0x000000d8, 0x000000f8, 0x000000d0, 0x000000f0, 0x000000d9, 0x000000f9, 0x000000a5, 0x0000001c, 0x000000a8, 0x00000012, 0x0000001b, 0x000000a0, 0x00000013, 0x000000a9, 0x00000005, 0x000000b5, 0x0000000a, 0x000000b8, 0x00000003, 0x000000b0, 0x0000000b, 0x000000b9, 0x00000032, 0x00000088, 0x0000003c, 0x00000085, 0x0000008d, 0x00000034, 0x00000084, 0x0000003d, 0x00000091, 0x00000022, 0x0000009c, 0x0000002c, 0x00000094, 0x00000024, 0x0000009d, 0x0000002d, 0x00000062, 0x0000004a, 0x0000006c, 0x00000045, 0x0000004d, 0x00000064, 0x00000044, 0x0000006d, 0x00000052, 0x00000072, 0x0000005c, 0x0000007c, 0x00000054, 0x00000074, 0x0000005d, 0x0000007d, 0x000000a1, 0x0000001a, 0x000000ac, 0x00000015, 0x0000001d, 0x000000a4, 0x00000014, 0x000000ad, 0x00000002, 0x000000b1, 0x0000000c, 0x000000bc, 0x00000004, 0x000000b4, 0x0000000d, 0x000000bd, 0x000000e1, 0x000000c8, 0x000000ec, 0x000000c5, 0x000000cd, 0x000000e4, 0x000000c4, 0x000000ed, 0x000000d1, 0x000000f1, 0x000000dc, 0x000000fc, 0x000000d4, 0x000000f4, 0x000000dd, 0x000000fd, 0x00000036, 0x0000008e, 0x00000038, 0x00000082, 0x0000008b, 0x00000030, 0x00000083, 0x00000039, 0x00000096, 0x00000026, 0x0000009a, 0x00000028, 0x00000093, 0x00000020, 0x0000009b, 0x00000029, 0x00000066, 0x0000004e, 0x00000068, 0x00000041, 0x00000049, 0x00000060, 0x00000040, 0x00000069, 0x00000056, 0x00000076, 0x00000058, 0x00000078, 0x00000050, 0x00000070, 0x00000059, 0x00000079, 0x000000a6, 0x0000001e, 0x000000aa, 0x00000011, 0x00000019, 0x000000a3, 0x00000010, 0x000000ab, 0x00000006, 0x000000b6, 0x00000008, 0x000000ba, 0x00000000, 0x000000b3, 0x00000009, 0x000000bb, 0x000000e6, 0x000000ce, 0x000000ea, 0x000000c2, 0x000000cb, 0x000000e3, 0x000000c3, 0x000000eb, 0x000000d6, 0x000000f6, 0x000000da, 0x000000fa, 0x000000d3, 0x000000f3, 0x000000db, 0x000000fb, 0x00000031, 0x0000008a, 0x0000003e, 0x00000086, 0x0000008f, 0x00000037, 0x00000087, 0x0000003f, 0x00000092, 0x00000021, 0x0000009e, 0x0000002e, 0x00000097, 0x00000027, 0x0000009f, 0x0000002f, 0x00000061, 0x00000048, 0x0000006e, 0x00000046, 0x0000004f, 0x00000067, 0x00000047, 0x0000006f, 0x00000051, 0x00000071, 0x0000005e, 0x0000007e, 0x00000057, 0x00000077, 0x0000005f, 0x0000007f, 0x000000a2, 0x00000018, 0x000000ae, 0x00000016, 0x0000001f, 0x000000a7, 0x00000017, 0x000000af, 0x00000001, 0x000000b2, 0x0000000e, 0x000000be, 0x00000007, 0x000000b7, 0x0000000f, 0x000000bf, 0x000000e2, 0x000000ca, 0x000000ee, 0x000000c6, 0x000000cf, 0x000000e7, 0x000000c7, 0x000000ef, 0x000000d2, 0x000000f2, 0x000000de, 0x000000fe, 0x000000d7, 0x000000f7, 0x000000df, 0x000000ff};

static const uint32_t AC_column0[87] = {0x1000101, 0x3000303, 0x7000707, 0xf000f0f, 0xf000f0f, 0xf000f0f, 0xe000e0e, 0xd000d0d, 0xb000b0b, 0x7000707, 0xf000f0f, 0xf000f0f, 0xe000e0e, 0xc000c0c, 0x9000909, 0x3000303, 0x7000707, 0xf000f0f, 0xe000e0e, 0xd000d0d, 0xa000a0a, 0x5000505, 0xb000b0b, 0x7000707, 0xe000e0e, 0xc000c0c, 0x8000808, 0x0, 0x1000101, 0x3000303, 0x6000606, 0xd000d0d, 0xb000b0b, 0x7000707, 0xe000e0e, 0xd000d0d, 0xa000a0a, 0x4000404, 0x9000909, 0x3000303, 0x6000606, 0xc000c0c, 0x8000808, 0x1000101, 0x2000202, 0x5000505, 0xa000a0a, 0x5000505, 0xb000b0b, 0x6000606, 0xc000c0c, 0x8000808, 0x0, 0x0, 0x1000101, 0x2000202, 0x5000505, 0xb000b0b, 0x7000707, 0xf000f0f, 0xe000e0e, 0xc000c0c, 0x8000808, 0x1000101, 0x3000303, 0x7000707, 0xe000e0e, 0xd000d0d, 0xb000b0b, 0x6000606, 0xd000d0d, 0xb000b0b, 0x6000606, 0xc000c0c, 0x9000909, 0x2000202, 0x4000404, 0x9000909, 0x2000202, 0x5000505, 0xa000a0a, 0x4000404, 0x9000909, 0x2000202, 0x4000404, 0x8000808, 0x0};
static const uint32_t AC_column1[87] = {0x0, 0x0, 0x0, 0x0, 0x10000, 0x30000, 0x70000, 0x70000, 0x70000, 0x70000, 0x60000, 0x50000, 0x30000, 0x70000, 0x70000, 0x70000, 0x60000, 0x40000, 0x10000, 0x30000, 0x70000, 0x70000, 0x60000, 0x50000, 0x20000, 0x50000, 0x30000, 0x70000, 0x60000, 0x40000, 0x0, 0x0, 0x10000, 0x30000, 0x60000, 0x50000, 0x30000, 0x70000, 0x60000, 0x50000, 0x20000, 0x40000, 0x10000, 0x30000, 0x60000, 0x40000, 0x0, 0x10000, 0x20000, 0x50000, 0x20000, 0x50000, 0x30000, 0x60000, 0x40000, 0x0, 0x0, 0x0, 0x10000, 0x20000, 0x50000, 0x30000, 0x70000, 0x70000, 0x60000, 0x40000, 0x0, 0x10000, 0x30000, 0x70000, 0x60000, 0x50000, 0x30000, 0x60000, 0x50000, 0x30000, 0x60000, 0x40000, 0x10000, 0x20000, 0x40000, 0x10000, 0x20000, 0x50000, 0x20000, 0x40000, 0x10000};


/**
 * \brief Number of rounds of ForkSkinny-128-256 before forking.
 */
#define FORKSKINNY_128_256_ROUNDS_BEFORE 21

/**
 * \brief Number of rounds of ForkSkinny-128-256 after forking.
 */
#define FORKSKINNY_128_256_ROUNDS_AFTER 27

/**
 * \brief State information for ForkSkinny-128-256.
 */
typedef struct
{
    uint32_t TK1[4];        /**< First part of the tweakey */
    uint32_t TK2[4];        /**< Second part of the tweakey */
    uint32_t S[4];          /**< Current block state */

} forkskinny_128_256_state_t;

#define TK_to_column_256(columns, state) \
	do { \
		uint32_t TK0 = state->TK1[0] ^ state->TK2[0];\
		uint32_t TK1 = state->TK1[1] ^ state->TK2[1]; \
		uint32_t tk00 = TK0 & 0xFF; \
		uint32_t tk01 = TK0 & 0xFF00;\
		uint32_t tk02 = TK0 & 0xFF0000;\
		uint32_t tk03 = TK0 & 0xFF000000;\
		columns[0] = tk00 << 24 | (TK1 & 0xFF000000) >> 8 	| tk00 << 8  | tk00; \
		columns[1] = tk01 << 16 | (TK1 & 0xFF) 	   << 16	| tk01  	 | tk01 >> 8; \
		columns[2] = tk02 << 8  | (TK1 & 0xFF00)     << 8 	| tk02 >> 8  | tk02 >> 16; \
		columns[3] = tk03       | (TK1 & 0xFF0000)  		| tk03 >> 16 | tk03 >> 24; \
	} while(0)


/**
 * \brief Applies one round of ForkSkinny-128-256.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_128_256_round_table
    (forkskinny_128_256_state_t *state, unsigned round)
{
    uint32_t s0, s1, s2, s3;
    uint32_t tk_columns[4];

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    TK_to_column_256(tk_columns, state);

    state->S[0] = T0[s0 & 0xff] ^ T1[(s3>>8) & 0xff] ^ T2[(s2>>16) & 0xff] ^ T3[(s1>>24)] ^ tk_columns[0] ^ AC_column0[round];
    state->S[1] = T0[s1 & 0xff] ^ T1[(s0>>8) & 0xff] ^ T2[(s3>>16) & 0xff] ^ T3[(s2>>24)] ^ tk_columns[1] ^ AC_column1[round];
    state->S[2] = T0[s2 & 0xff] ^ T1[(s1>>8) & 0xff] ^ T2[(s0>>16) & 0xff] ^ T3[(s3>>24)] ^ tk_columns[2] ^ 0x00020200;
    state->S[3] = T0[s3 & 0xff] ^ T1[(s2>>8) & 0xff] ^ T2[(s1>>16) & 0xff] ^ T3[(s0>>24)] ^ tk_columns[3];


    /* Permute TK1 and TK2 for the next round */
    skinny128_permute_tk(state->TK1);
    skinny128_permute_tk(state->TK2);
    skinny128_LFSR2(state->TK2[0]);
    skinny128_LFSR2(state->TK2[1]);
}

#define load_column(dest, src) \
	do { \
		dest[0] = (src[12]) << 24 | (src[8])  << 16 | (src[4]) << 8 | (src[0]); \
		dest[1] = (src[13]) << 24 | (src[9])  << 16 | (src[5]) << 8 | (src[1]); \
		dest[2] = (src[14]) << 24 | (src[10]) << 16 | (src[6]) << 8 | (src[2]); \
		dest[3] = (src[15]) << 24 | (src[11]) << 16 | (src[7]) << 8 | (src[3]); \
	} while(0)

#define store_column(dest, src) \
	do { \
		dest[0] = (uint8_t) (src[0]); 	 dest[1] = (uint8_t) (src[1]); 	  dest[2] = (uint8_t) (src[2]);    dest[3] = (uint8_t) (src[3]); \
		dest[4] = (uint8_t) (src[0]>>8); dest[5] = (uint8_t) (src[1]>>8); dest[6] = (uint8_t) (src[2]>>8); dest[7] = (uint8_t) (src[3]>>8); \
		dest[8] = (uint8_t) (src[0]>>16);dest[9] = (uint8_t) (src[1]>>16);dest[10]= (uint8_t) (src[2]>>16);dest[11]= (uint8_t)(src[3]>>16); \
		dest[12]= (uint8_t) (src[0]>>24);dest[13]= (uint8_t) (src[1]>>24);dest[14]= (uint8_t) (src[2]>>24);dest[15]= (uint8_t)(src[3]>>24); \
	} while(0)

void forkskinny_128_256_encrypt
    (const unsigned char key[32], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_128_256_state_t state;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = le_load_word32(key);
    state.TK1[1] = le_load_word32(key + 4);
    state.TK1[2] = le_load_word32(key + 8);
    state.TK1[3] = le_load_word32(key + 12);
    state.TK2[0] = le_load_word32(key + 16);
    state.TK2[1] = le_load_word32(key + 20);
    state.TK2[2] = le_load_word32(key + 24);
    state.TK2[3] = le_load_word32(key + 28);

    /* State stored per column */
    load_column(state.S, input);

    /* Run all of the rounds before the forking point */
    for (round = 0; round < FORKSKINNY_128_256_ROUNDS_BEFORE; ++round) {
        forkskinny_128_256_round_table(&state, round);
    }

    /* Determine which output blocks we need */
    if (output_left && output_right) {
        /* We need both outputs so save the state at the forking point */
        uint32_t F[4];
        F[0] = state.S[0];
        F[1] = state.S[1];
        F[2] = state.S[2];
        F[3] = state.S[3];

        /* Generate the right output block */
        for (round = FORKSKINNY_128_256_ROUNDS_BEFORE;
                round < (FORKSKINNY_128_256_ROUNDS_BEFORE +
                         FORKSKINNY_128_256_ROUNDS_AFTER); ++round) {
            forkskinny_128_256_round_table(&state, round);
        }
        store_column(output_right, state.S);
        /* Restore the state at the forking point */
        state.S[0] = F[0];
        state.S[1] = F[1];
        state.S[2] = F[2];
        state.S[3] = F[3];
    }
    if (output_left) {
        /* Generate the left output block */
    	state.S[0] ^= 0x51051001; /* Branching constant */
    	state.S[1] ^= 0xa20a2002;
    	state.S[2] ^= 0x44144104;
    	state.S[3] ^= 0x88288208;

        for (round = (FORKSKINNY_128_256_ROUNDS_BEFORE +
                      FORKSKINNY_128_256_ROUNDS_AFTER);
                round < (FORKSKINNY_128_256_ROUNDS_BEFORE +
                          FORKSKINNY_128_256_ROUNDS_AFTER * 2); ++round) {
            forkskinny_128_256_round_table(&state, round);
        }
        store_column(output_left, state.S);
    } else {
        /* We only need the right output block */
        for (round = FORKSKINNY_128_256_ROUNDS_BEFORE;
                round < (FORKSKINNY_128_256_ROUNDS_BEFORE +
                         FORKSKINNY_128_256_ROUNDS_AFTER); ++round) {
            forkskinny_128_256_round_table(&state, round);
        }
        store_column(output_right, state.S);
    }
}

/**
 * \brief Applies one round of ForkSkinny-128-256.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_128_256_round
    (forkskinny_128_256_state_t *state, unsigned round)
{
    uint32_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Apply the S-box to all cells in the state */
    skinny128_sbox(s0);
    skinny128_sbox(s1);
    skinny128_sbox(s2);
    skinny128_sbox(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ (rc & 0x0F) ^ 0x00020000;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ (rc >> 4);
    s2 ^= 0x02;

    /* Shift the cells in the rows right, which moves the cell
     * values up closer to the MSB.  That is, we do a left rotate
     * on the word to rotate the cells in the word right */
    s1 = leftRotate8(s1);
    s2 = leftRotate16(s2);
    s3 = leftRotate24(s3);

    /* Mix the columns */
    s1 ^= s2;
    s2 ^= s0;
    temp = s3 ^ s2;
    s3 = s2;
    s2 = s1;
    s1 = s0;
    s0 = temp;

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;

    /* Permute TK1 and TK2 for the next round */
    skinny128_permute_tk(state->TK1);
    skinny128_permute_tk(state->TK2);
    skinny128_LFSR2(state->TK2[0]);
    skinny128_LFSR2(state->TK2[1]);
}

/**
 * \brief Applies one round of ForkSkinny-128-256 in reverse.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_128_256_inv_round
    (forkskinny_128_256_state_t *state, unsigned round)
{
    uint32_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Permute TK1 and TK2 for the next round */
    skinny128_inv_LFSR2(state->TK2[0]);
    skinny128_inv_LFSR2(state->TK2[1]);
    skinny128_inv_permute_tk(state->TK1);
    skinny128_inv_permute_tk(state->TK2);

    /* Inverse mix of the columns */
    temp = s0;
    s0 = s1;
    s1 = s2;
    s2 = s3;
    s3 = temp ^ s2;
    s2 ^= s0;
    s1 ^= s2;

    /* Shift the cells in the rows left, which moves the cell
     * values down closer to the LSB.  That is, we do a right
     * rotate on the word to rotate the cells in the word left */
    s1 = rightRotate8(s1);
    s2 = rightRotate16(s2);
    s3 = rightRotate24(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ (rc & 0x0F) ^ 0x00020000;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ (rc >> 4);
    s2 ^= 0x02;

    /* Apply the inverse of the S-box to all cells in the state */
    skinny128_inv_sbox(s0);
    skinny128_inv_sbox(s1);
    skinny128_inv_sbox(s2);
    skinny128_inv_sbox(s3);

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_128_256_decrypt
    (const unsigned char key[32], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_128_256_state_t state;
    forkskinny_128_256_state_t fstate;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = le_load_word32(key);
    state.TK1[1] = le_load_word32(key + 4);
    state.TK1[2] = le_load_word32(key + 8);
    state.TK1[3] = le_load_word32(key + 12);
    state.TK2[0] = le_load_word32(key + 16);
    state.TK2[1] = le_load_word32(key + 20);
    state.TK2[2] = le_load_word32(key + 24);
    state.TK2[3] = le_load_word32(key + 28);
    state.S[0] = le_load_word32(input);
    state.S[1] = le_load_word32(input + 4);
    state.S[2] = le_load_word32(input + 8);
    state.S[3] = le_load_word32(input + 12);

    /* Fast-forward the tweakey to the end of the key schedule */
    for (round = 0; round < (FORKSKINNY_128_256_ROUNDS_BEFORE +
                             FORKSKINNY_128_256_ROUNDS_AFTER * 2); ++round) {
        skinny128_permute_tk(state.TK1);
        skinny128_permute_tk(state.TK2);
        skinny128_LFSR2(state.TK2[0]);
        skinny128_LFSR2(state.TK2[1]);
    }

    /* Perform the "after" rounds on the input to get back
     * to the forking point in the cipher */
    for (round = (FORKSKINNY_128_256_ROUNDS_BEFORE +
                  FORKSKINNY_128_256_ROUNDS_AFTER * 2);
            round > (FORKSKINNY_128_256_ROUNDS_BEFORE +
                     FORKSKINNY_128_256_ROUNDS_AFTER); --round) {
        forkskinny_128_256_inv_round(&state, round - 1);
    }

    /* Remove the branching constant */
    state.S[0] ^= 0x08040201U;
    state.S[1] ^= 0x82412010U;
    state.S[2] ^= 0x28140a05U;
    state.S[3] ^= 0x8844a251U;

    /* Roll the tweakey back another "after" rounds */
    for (round = 0; round < FORKSKINNY_128_256_ROUNDS_AFTER; ++round) {
        skinny128_inv_LFSR2(state.TK2[0]);
        skinny128_inv_LFSR2(state.TK2[1]);
        skinny128_inv_permute_tk(state.TK1);
        skinny128_inv_permute_tk(state.TK2);
    }

    /* Save the state and the tweakey at the forking point */
    fstate = state;

    /* Generate the left output block after another "before" rounds */
    for (round = FORKSKINNY_128_256_ROUNDS_BEFORE; round > 0; --round) {
        forkskinny_128_256_inv_round(&state, round - 1);
    }
    le_store_word32(output_left,      state.S[0]);
    le_store_word32(output_left + 4,  state.S[1]);
    le_store_word32(output_left + 8,  state.S[2]);
    le_store_word32(output_left + 12, state.S[3]);

    /* Generate the right output block by going forward "after"
     * rounds from the forking point */
    for (round = FORKSKINNY_128_256_ROUNDS_BEFORE;
            round < (FORKSKINNY_128_256_ROUNDS_BEFORE +
                     FORKSKINNY_128_256_ROUNDS_AFTER); ++round) {
        forkskinny_128_256_round(&fstate, round);
    }
    le_store_word32(output_right,      fstate.S[0]);
    le_store_word32(output_right + 4,  fstate.S[1]);
    le_store_word32(output_right + 8,  fstate.S[2]);
    le_store_word32(output_right + 12, fstate.S[3]);
}

/**
 * \brief Number of rounds of ForkSkinny-128-384 before forking.
 */
#define FORKSKINNY_128_384_ROUNDS_BEFORE 25

/**
 * \brief Number of rounds of ForkSkinny-128-384 after forking.
 */
#define FORKSKINNY_128_384_ROUNDS_AFTER 31

/**
 * \brief State information for ForkSkinny-128-384.
 */
typedef struct
{
    uint32_t TK1[4];        /**< First part of the tweakey */
    uint32_t TK2[4];        /**< Second part of the tweakey */
    uint32_t TK3[4];        /**< Third part of the tweakey */
    uint32_t S[4];          /**< Current block state */

} forkskinny_128_384_state_t;

#define TK_to_column_384(columns, state) \
	do { \
		uint32_t TK0 = state->TK1[0] ^ state->TK2[0] ^ state->TK3[0];\
		uint32_t TK1 = state->TK1[1] ^ state->TK2[1] ^ state->TK3[1];\
		uint32_t tk00 = TK0 & 0xFF; \
		uint32_t tk01 = TK0 & 0xFF00;\
		uint32_t tk02 = TK0 & 0xFF0000;\
		uint32_t tk03 = TK0 & 0xFF000000;\
		columns[0] = tk00 << 24 | (TK1 & 0xFF000000) >> 8 	| tk00 << 8  | tk00; \
		columns[1] = tk01 << 16 | (TK1 & 0xFF) 	   << 16	| tk01  	 | tk01 >> 8; \
		columns[2] = tk02 << 8  | (TK1 & 0xFF00)     << 8 	| tk02 >> 8  | tk02 >> 16; \
		columns[3] = tk03       | (TK1 & 0xFF0000)  		| tk03 >> 16 | tk03 >> 24; \
	} while(0)

/**
 * \brief Applies one round of ForkSkinny-128-384.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_128_384_round_table
    (forkskinny_128_384_state_t *state, unsigned round)
{
    uint32_t s0, s1, s2, s3;
    uint32_t tk_columns[4];

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    TK_to_column_384(tk_columns, state);

    state->S[0] = T0[s0 & 0xff] ^ T1[(s3>>8) & 0xff] ^ T2[(s2>>16) & 0xff] ^ T3[(s1>>24)] ^ tk_columns[0] ^ AC_column0[round];
    state->S[1] = T0[s1 & 0xff] ^ T1[(s0>>8) & 0xff] ^ T2[(s3>>16) & 0xff] ^ T3[(s2>>24)] ^ tk_columns[1] ^ AC_column1[round];
    state->S[2] = T0[s2 & 0xff] ^ T1[(s1>>8) & 0xff] ^ T2[(s0>>16) & 0xff] ^ T3[(s3>>24)] ^ tk_columns[2] ^ 0x00020200;
    state->S[3] = T0[s3 & 0xff] ^ T1[(s2>>8) & 0xff] ^ T2[(s1>>16) & 0xff] ^ T3[(s0>>24)] ^ tk_columns[3];

    /* Permute TK1, TK2, and TK3 for the next round */
    skinny128_permute_tk(state->TK1);
    skinny128_permute_tk(state->TK2);
    skinny128_permute_tk(state->TK3);
    skinny128_LFSR2(state->TK2[0]);
    skinny128_LFSR2(state->TK2[1]);
    skinny128_LFSR3(state->TK3[0]);
    skinny128_LFSR3(state->TK3[1]);
}

void forkskinny_128_384_encrypt
    (const unsigned char key[48], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_128_384_state_t state;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = le_load_word32(key);
    state.TK1[1] = le_load_word32(key + 4);
    state.TK1[2] = le_load_word32(key + 8);
    state.TK1[3] = le_load_word32(key + 12);
    state.TK2[0] = le_load_word32(key + 16);
    state.TK2[1] = le_load_word32(key + 20);
    state.TK2[2] = le_load_word32(key + 24);
    state.TK2[3] = le_load_word32(key + 28);
    state.TK3[0] = le_load_word32(key + 32);
    state.TK3[1] = le_load_word32(key + 36);
    state.TK3[2] = le_load_word32(key + 40);
    state.TK3[3] = le_load_word32(key + 44);

    /* State stored per column */
    load_column(state.S, input);

    /* Run all of the rounds before the forking point */
    for (round = 0; round < FORKSKINNY_128_384_ROUNDS_BEFORE; ++round) {
        forkskinny_128_384_round_table(&state, round);
    }

    /* Determine which output blocks we need */
    if (output_left && output_right) {
        /* We need both outputs so save the state at the forking point */
        uint32_t F[4];
        F[0] = state.S[0];
        F[1] = state.S[1];
        F[2] = state.S[2];
        F[3] = state.S[3];

        /* Generate the right output block */
        for (round = FORKSKINNY_128_384_ROUNDS_BEFORE;
                round < (FORKSKINNY_128_384_ROUNDS_BEFORE +
                         FORKSKINNY_128_384_ROUNDS_AFTER); ++round) {
            forkskinny_128_384_round_table(&state, round);
        }
        store_column(output_right, state.S);

        /* Restore the state at the forking point */
        state.S[0] = F[0];
        state.S[1] = F[1];
        state.S[2] = F[2];
        state.S[3] = F[3];
    }
    if (output_left) {
        /* Generate the left output block */
        state.S[0] ^= 0x51051001; /* Branching constant */
    	state.S[1] ^= 0xa20a2002;
    	state.S[2] ^= 0x44144104;
    	state.S[3] ^= 0x88288208;
        for (round = (FORKSKINNY_128_384_ROUNDS_BEFORE +
                      FORKSKINNY_128_384_ROUNDS_AFTER);
                round < (FORKSKINNY_128_384_ROUNDS_BEFORE +
                          FORKSKINNY_128_384_ROUNDS_AFTER * 2); ++round) {
            forkskinny_128_384_round_table(&state, round);
        }
        store_column(output_left, state.S);

    } else {
        /* We only need the right output block */
        for (round = FORKSKINNY_128_384_ROUNDS_BEFORE;
                round < (FORKSKINNY_128_384_ROUNDS_BEFORE +
                         FORKSKINNY_128_384_ROUNDS_AFTER); ++round) {
            forkskinny_128_384_round_table(&state, round);
        }
        store_column(output_right, state.S);
    }
}

/**
 * \brief Applies one round of ForkSkinny-128-384.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_128_384_round
    (forkskinny_128_384_state_t *state, unsigned round)
{
    uint32_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Apply the S-box to all cells in the state */
    skinny128_sbox(s0);
    skinny128_sbox(s1);
    skinny128_sbox(s2);
    skinny128_sbox(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
          (rc & 0x0F) ^ 0x00020000;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^ (rc >> 4);
    s2 ^= 0x02;

    /* Shift the cells in the rows right, which moves the cell
     * values up closer to the MSB.  That is, we do a left rotate
     * on the word to rotate the cells in the word right */
    s1 = leftRotate8(s1);
    s2 = leftRotate16(s2);
    s3 = leftRotate24(s3);

    /* Mix the columns */
    s1 ^= s2;
    s2 ^= s0;
    temp = s3 ^ s2;
    s3 = s2;
    s2 = s1;
    s1 = s0;
    s0 = temp;

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;

    /* Permute TK1, TK2, and TK3 for the next round */
    skinny128_permute_tk(state->TK1);
    skinny128_permute_tk(state->TK2);
    skinny128_permute_tk(state->TK3);
    skinny128_LFSR2(state->TK2[0]);
    skinny128_LFSR2(state->TK2[1]);
    skinny128_LFSR3(state->TK3[0]);
    skinny128_LFSR3(state->TK3[1]);
}

/**
 * \brief Applies one round of ForkSkinny-128-384 in reverse.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_128_384_inv_round
    (forkskinny_128_384_state_t *state, unsigned round)
{
    uint32_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Permute TK1 and TK2 for the next round */
    skinny128_inv_LFSR2(state->TK2[0]);
    skinny128_inv_LFSR2(state->TK2[1]);
    skinny128_inv_LFSR3(state->TK3[0]);
    skinny128_inv_LFSR3(state->TK3[1]);
    skinny128_inv_permute_tk(state->TK1);
    skinny128_inv_permute_tk(state->TK2);
    skinny128_inv_permute_tk(state->TK3);

    /* Inverse mix of the columns */
    temp = s0;
    s0 = s1;
    s1 = s2;
    s2 = s3;
    s3 = temp ^ s2;
    s2 ^= s0;
    s1 ^= s2;

    /* Shift the cells in the rows left, which moves the cell
     * values down closer to the LSB.  That is, we do a right
     * rotate on the word to rotate the cells in the word left */
    s1 = rightRotate8(s1);
    s2 = rightRotate16(s2);
    s3 = rightRotate24(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
          (rc & 0x0F) ^ 0x00020000;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^ (rc >> 4);
    s2 ^= 0x02;

    /* Apply the inverse of the S-box to all cells in the state */
    skinny128_inv_sbox(s0);
    skinny128_inv_sbox(s1);
    skinny128_inv_sbox(s2);
    skinny128_inv_sbox(s3);

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_128_384_decrypt
    (const unsigned char key[48], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_128_384_state_t state;
    forkskinny_128_384_state_t fstate;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = le_load_word32(key);
    state.TK1[1] = le_load_word32(key + 4);
    state.TK1[2] = le_load_word32(key + 8);
    state.TK1[3] = le_load_word32(key + 12);
    state.TK2[0] = le_load_word32(key + 16);
    state.TK2[1] = le_load_word32(key + 20);
    state.TK2[2] = le_load_word32(key + 24);
    state.TK2[3] = le_load_word32(key + 28);
    state.TK3[0] = le_load_word32(key + 32);
    state.TK3[1] = le_load_word32(key + 36);
    state.TK3[2] = le_load_word32(key + 40);
    state.TK3[3] = le_load_word32(key + 44);
    state.S[0] = le_load_word32(input);
    state.S[1] = le_load_word32(input + 4);
    state.S[2] = le_load_word32(input + 8);
    state.S[3] = le_load_word32(input + 12);

    /* Fast-forward the tweakey to the end of the key schedule */
    for (round = 0; round < (FORKSKINNY_128_384_ROUNDS_BEFORE +
                             FORKSKINNY_128_384_ROUNDS_AFTER * 2); ++round) {
        skinny128_permute_tk(state.TK1);
        skinny128_permute_tk(state.TK2);
        skinny128_permute_tk(state.TK3);
        skinny128_LFSR2(state.TK2[0]);
        skinny128_LFSR2(state.TK2[1]);
        skinny128_LFSR3(state.TK3[0]);
        skinny128_LFSR3(state.TK3[1]);
    }

    /* Perform the "after" rounds on the input to get back
     * to the forking point in the cipher */
    for (round = (FORKSKINNY_128_384_ROUNDS_BEFORE +
                  FORKSKINNY_128_384_ROUNDS_AFTER * 2);
            round > (FORKSKINNY_128_384_ROUNDS_BEFORE +
                     FORKSKINNY_128_384_ROUNDS_AFTER); --round) {
        forkskinny_128_384_inv_round(&state, round - 1);
    }

    /* Remove the branching constant */
    state.S[0] ^= 0x08040201U;
    state.S[1] ^= 0x82412010U;
    state.S[2] ^= 0x28140a05U;
    state.S[3] ^= 0x8844a251U;

    /* Roll the tweakey back another "after" rounds */
    for (round = 0; round < FORKSKINNY_128_384_ROUNDS_AFTER; ++round) {
        skinny128_inv_LFSR2(state.TK2[0]);
        skinny128_inv_LFSR2(state.TK2[1]);
        skinny128_inv_LFSR3(state.TK3[0]);
        skinny128_inv_LFSR3(state.TK3[1]);
        skinny128_inv_permute_tk(state.TK1);
        skinny128_inv_permute_tk(state.TK2);
        skinny128_inv_permute_tk(state.TK3);
    }

    /* Save the state and the tweakey at the forking point */
    fstate = state;

    /* Generate the left output block after another "before" rounds */
    for (round = FORKSKINNY_128_384_ROUNDS_BEFORE; round > 0; --round) {
        forkskinny_128_384_inv_round(&state, round - 1);
    }
    le_store_word32(output_left,      state.S[0]);
    le_store_word32(output_left + 4,  state.S[1]);
    le_store_word32(output_left + 8,  state.S[2]);
    le_store_word32(output_left + 12, state.S[3]);

    /* Generate the right output block by going forward "after"
     * rounds from the forking point */
    for (round = FORKSKINNY_128_384_ROUNDS_BEFORE;
            round < (FORKSKINNY_128_384_ROUNDS_BEFORE +
                     FORKSKINNY_128_384_ROUNDS_AFTER); ++round) {
        forkskinny_128_384_round(&fstate, round);
    }
    le_store_word32(output_right,      fstate.S[0]);
    le_store_word32(output_right + 4,  fstate.S[1]);
    le_store_word32(output_right + 8,  fstate.S[2]);
    le_store_word32(output_right + 12, fstate.S[3]);
}

/**
 * \brief Number of rounds of ForkSkinny-64-192 before forking.
 */
#define FORKSKINNY_64_192_ROUNDS_BEFORE 17

/**
 * \brief Number of rounds of ForkSkinny-64-192 after forking.
 */
#define FORKSKINNY_64_192_ROUNDS_AFTER 23

/**
 * \brief State information for ForkSkinny-64-192.
 */
typedef struct
{
    uint16_t TK1[4];    /**< First part of the tweakey */
    uint16_t TK2[4];    /**< Second part of the tweakey */
    uint16_t TK3[4];    /**< Third part of the tweakey */
    uint16_t S[4];      /**< Current block state */

} forkskinny_64_192_state_t;

/**
 * \brief Applies one round of ForkSkinny-64-192.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 *
 * Note: The cells of each row are order in big-endian nibble order
 * so it is easiest to manage the rows in bit-endian byte order.
 */
static void forkskinny_64_192_round
    (forkskinny_64_192_state_t *state, unsigned round)
{
    uint16_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Apply the S-box to all cells in the state */
    skinny64_sbox(s0);
    skinny64_sbox(s1);
    skinny64_sbox(s2);
    skinny64_sbox(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
          ((rc & 0x0F) << 12) ^ 0x0020;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^
          ((rc & 0x70) << 8);
    s2 ^= 0x2000;

    /* Shift the cells in the rows right */
    s1 = rightRotate4_16(s1);
    s2 = rightRotate8_16(s2);
    s3 = rightRotate12_16(s3);

    /* Mix the columns */
    s1 ^= s2;
    s2 ^= s0;
    temp = s3 ^ s2;
    s3 = s2;
    s2 = s1;
    s1 = s0;
    s0 = temp;

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;

    /* Permute TK1, TK2, and TK3 for the next round */
    skinny64_permute_tk(state->TK1);
    skinny64_permute_tk(state->TK2);
    skinny64_permute_tk(state->TK3);
    skinny64_LFSR2(state->TK2[0]);
    skinny64_LFSR2(state->TK2[1]);
    skinny64_LFSR3(state->TK3[0]);
    skinny64_LFSR3(state->TK3[1]);
}

void forkskinny_64_192_encrypt
    (const unsigned char key[24], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_64_192_state_t state;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = be_load_word16(key);
    state.TK1[1] = be_load_word16(key + 2);
    state.TK1[2] = be_load_word16(key + 4);
    state.TK1[3] = be_load_word16(key + 6);
    state.TK2[0] = be_load_word16(key + 8);
    state.TK2[1] = be_load_word16(key + 10);
    state.TK2[2] = be_load_word16(key + 12);
    state.TK2[3] = be_load_word16(key + 14);
    state.TK3[0] = be_load_word16(key + 16);
    state.TK3[1] = be_load_word16(key + 18);
    state.TK3[2] = be_load_word16(key + 20);
    state.TK3[3] = be_load_word16(key + 22);
    state.S[0] = be_load_word16(input);
    state.S[1] = be_load_word16(input + 2);
    state.S[2] = be_load_word16(input + 4);
    state.S[3] = be_load_word16(input + 6);

    /* Run all of the rounds before the forking point */
    for (round = 0; round < FORKSKINNY_64_192_ROUNDS_BEFORE; ++round) {
        forkskinny_64_192_round(&state, round);
    }

    /* Determine which output blocks we need */
    if (output_left && output_right) {
        /* We need both outputs so save the state at the forking point */
        uint16_t F[4];
        F[0] = state.S[0];
        F[1] = state.S[1];
        F[2] = state.S[2];
        F[3] = state.S[3];

        /* Generate the right output block */
        for (round = FORKSKINNY_64_192_ROUNDS_BEFORE;
                round < (FORKSKINNY_64_192_ROUNDS_BEFORE +
                         FORKSKINNY_64_192_ROUNDS_AFTER); ++round) {
            forkskinny_64_192_round(&state, round);
        }
        be_store_word16(output_right,     state.S[0]);
        be_store_word16(output_right + 2, state.S[1]);
        be_store_word16(output_right + 4, state.S[2]);
        be_store_word16(output_right + 6, state.S[3]);

        /* Restore the state at the forking point */
        state.S[0] = F[0];
        state.S[1] = F[1];
        state.S[2] = F[2];
        state.S[3] = F[3];
    }
    if (output_left) {
        /* Generate the left output block */
        state.S[0] ^= 0x1249U;  /* Branching constant */
        state.S[1] ^= 0x36daU;
        state.S[2] ^= 0x5b7fU;
        state.S[3] ^= 0xec81U;
        for (round = (FORKSKINNY_64_192_ROUNDS_BEFORE +
                      FORKSKINNY_64_192_ROUNDS_AFTER);
                round < (FORKSKINNY_64_192_ROUNDS_BEFORE +
                          FORKSKINNY_64_192_ROUNDS_AFTER * 2); ++round) {
            forkskinny_64_192_round(&state, round);
        }
        be_store_word16(output_left,     state.S[0]);
        be_store_word16(output_left + 2, state.S[1]);
        be_store_word16(output_left + 4, state.S[2]);
        be_store_word16(output_left + 6, state.S[3]);
    } else {
        /* We only need the right output block */
        for (round = FORKSKINNY_64_192_ROUNDS_BEFORE;
                round < (FORKSKINNY_64_192_ROUNDS_BEFORE +
                         FORKSKINNY_64_192_ROUNDS_AFTER); ++round) {
            forkskinny_64_192_round(&state, round);
        }
        be_store_word16(output_right,     state.S[0]);
        be_store_word16(output_right + 2, state.S[1]);
        be_store_word16(output_right + 4, state.S[2]);
        be_store_word16(output_right + 6, state.S[3]);
    }
}

/**
 * \brief Applies one round of ForkSkinny-64-192 in reverse.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_64_192_inv_round
    (forkskinny_64_192_state_t *state, unsigned round)
{
    uint16_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Permute TK1, TK2, and TK3 for the next round */
    skinny64_inv_LFSR2(state->TK2[0]);
    skinny64_inv_LFSR2(state->TK2[1]);
    skinny64_inv_LFSR3(state->TK3[0]);
    skinny64_inv_LFSR3(state->TK3[1]);
    skinny64_inv_permute_tk(state->TK1);
    skinny64_inv_permute_tk(state->TK2);
    skinny64_inv_permute_tk(state->TK3);

    /* Inverse mix of the columns */
    temp = s0;
    s0 = s1;
    s1 = s2;
    s2 = s3;
    s3 = temp ^ s2;
    s2 ^= s0;
    s1 ^= s2;

    /* Shift the cells in the rows left */
    s1 = leftRotate4_16(s1);
    s2 = leftRotate8_16(s2);
    s3 = leftRotate12_16(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
          ((rc & 0x0F) << 12) ^ 0x0020;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^
          ((rc & 0x70) << 8);
    s2 ^= 0x2000;

    /* Apply the inverse of the S-box to all cells in the state */
    skinny64_inv_sbox(s0);
    skinny64_inv_sbox(s1);
    skinny64_inv_sbox(s2);
    skinny64_inv_sbox(s3);

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_64_192_decrypt
    (const unsigned char key[24], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_64_192_state_t state;
    forkskinny_64_192_state_t fstate;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = be_load_word16(key);
    state.TK1[1] = be_load_word16(key + 2);
    state.TK1[2] = be_load_word16(key + 4);
    state.TK1[3] = be_load_word16(key + 6);
    state.TK2[0] = be_load_word16(key + 8);
    state.TK2[1] = be_load_word16(key + 10);
    state.TK2[2] = be_load_word16(key + 12);
    state.TK2[3] = be_load_word16(key + 14);
    state.TK3[0] = be_load_word16(key + 16);
    state.TK3[1] = be_load_word16(key + 18);
    state.TK3[2] = be_load_word16(key + 20);
    state.TK3[3] = be_load_word16(key + 22);
    state.S[0] = be_load_word16(input);
    state.S[1] = be_load_word16(input + 2);
    state.S[2] = be_load_word16(input + 4);
    state.S[3] = be_load_word16(input + 6);

    /* Fast-forward the tweakey to the end of the key schedule */
    for (round = 0; round < (FORKSKINNY_64_192_ROUNDS_BEFORE +
                             FORKSKINNY_64_192_ROUNDS_AFTER * 2); ++round) {
        skinny64_permute_tk(state.TK1);
        skinny64_permute_tk(state.TK2);
        skinny64_permute_tk(state.TK3);
        skinny64_LFSR2(state.TK2[0]);
        skinny64_LFSR2(state.TK2[1]);
        skinny64_LFSR3(state.TK3[0]);
        skinny64_LFSR3(state.TK3[1]);
    }

    /* Perform the "after" rounds on the input to get back
     * to the forking point in the cipher */
    for (round = (FORKSKINNY_64_192_ROUNDS_BEFORE +
                  FORKSKINNY_64_192_ROUNDS_AFTER * 2);
            round > (FORKSKINNY_64_192_ROUNDS_BEFORE +
                     FORKSKINNY_64_192_ROUNDS_AFTER); --round) {
        forkskinny_64_192_inv_round(&state, round - 1);
    }

    /* Remove the branching constant */
    state.S[0] ^= 0x1249U;
    state.S[1] ^= 0x36daU;
    state.S[2] ^= 0x5b7fU;
    state.S[3] ^= 0xec81U;

    /* Roll the tweakey back another "after" rounds */
    for (round = 0; round < FORKSKINNY_64_192_ROUNDS_AFTER; ++round) {
        skinny64_inv_LFSR2(state.TK2[0]);
        skinny64_inv_LFSR2(state.TK2[1]);
        skinny64_inv_LFSR3(state.TK3[0]);
        skinny64_inv_LFSR3(state.TK3[1]);
        skinny64_inv_permute_tk(state.TK1);
        skinny64_inv_permute_tk(state.TK2);
        skinny64_inv_permute_tk(state.TK3);
    }

    /* Save the state and the tweakey at the forking point */
    fstate = state;

    /* Generate the left output block after another "before" rounds */
    for (round = FORKSKINNY_64_192_ROUNDS_BEFORE; round > 0; --round) {
        forkskinny_64_192_inv_round(&state, round - 1);
    }
    be_store_word16(output_left,     state.S[0]);
    be_store_word16(output_left + 2, state.S[1]);
    be_store_word16(output_left + 4, state.S[2]);
    be_store_word16(output_left + 6, state.S[3]);

    /* Generate the right output block by going forward "after"
     * rounds from the forking point */
    for (round = FORKSKINNY_64_192_ROUNDS_BEFORE;
            round < (FORKSKINNY_64_192_ROUNDS_BEFORE +
                     FORKSKINNY_64_192_ROUNDS_AFTER); ++round) {
        forkskinny_64_192_round(&fstate, round);
    }
    be_store_word16(output_right,     fstate.S[0]);
    be_store_word16(output_right + 2, fstate.S[1]);
    be_store_word16(output_right + 4, fstate.S[2]);
    be_store_word16(output_right + 6, fstate.S[3]);
}

