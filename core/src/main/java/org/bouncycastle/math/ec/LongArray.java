package org.bouncycastle.math.ec;

import org.bouncycastle.util.Arrays;

import java.math.BigInteger;

class LongArray
{
//    private static long DEINTERLEAVE_MASK = 0x5555555555555555L;

    /*
     * This expands 8 bit indices into 16 bit contents (high bit 14), by inserting 0s between bits.
     * In a binary field, this operation is the same as squaring an 8 bit number.
     */
    private static final int[] INTERLEAVE2_TABLE = new int[]
    {
        0x0000, 0x0001, 0x0004, 0x0005, 0x0010, 0x0011, 0x0014, 0x0015,
        0x0040, 0x0041, 0x0044, 0x0045, 0x0050, 0x0051, 0x0054, 0x0055,
        0x0100, 0x0101, 0x0104, 0x0105, 0x0110, 0x0111, 0x0114, 0x0115,
        0x0140, 0x0141, 0x0144, 0x0145, 0x0150, 0x0151, 0x0154, 0x0155,
        0x0400, 0x0401, 0x0404, 0x0405, 0x0410, 0x0411, 0x0414, 0x0415,
        0x0440, 0x0441, 0x0444, 0x0445, 0x0450, 0x0451, 0x0454, 0x0455,
        0x0500, 0x0501, 0x0504, 0x0505, 0x0510, 0x0511, 0x0514, 0x0515,
        0x0540, 0x0541, 0x0544, 0x0545, 0x0550, 0x0551, 0x0554, 0x0555,
        0x1000, 0x1001, 0x1004, 0x1005, 0x1010, 0x1011, 0x1014, 0x1015,
        0x1040, 0x1041, 0x1044, 0x1045, 0x1050, 0x1051, 0x1054, 0x1055,
        0x1100, 0x1101, 0x1104, 0x1105, 0x1110, 0x1111, 0x1114, 0x1115,
        0x1140, 0x1141, 0x1144, 0x1145, 0x1150, 0x1151, 0x1154, 0x1155,
        0x1400, 0x1401, 0x1404, 0x1405, 0x1410, 0x1411, 0x1414, 0x1415,
        0x1440, 0x1441, 0x1444, 0x1445, 0x1450, 0x1451, 0x1454, 0x1455,
        0x1500, 0x1501, 0x1504, 0x1505, 0x1510, 0x1511, 0x1514, 0x1515,
        0x1540, 0x1541, 0x1544, 0x1545, 0x1550, 0x1551, 0x1554, 0x1555,
        0x4000, 0x4001, 0x4004, 0x4005, 0x4010, 0x4011, 0x4014, 0x4015,
        0x4040, 0x4041, 0x4044, 0x4045, 0x4050, 0x4051, 0x4054, 0x4055,
        0x4100, 0x4101, 0x4104, 0x4105, 0x4110, 0x4111, 0x4114, 0x4115,
        0x4140, 0x4141, 0x4144, 0x4145, 0x4150, 0x4151, 0x4154, 0x4155,
        0x4400, 0x4401, 0x4404, 0x4405, 0x4410, 0x4411, 0x4414, 0x4415,
        0x4440, 0x4441, 0x4444, 0x4445, 0x4450, 0x4451, 0x4454, 0x4455,
        0x4500, 0x4501, 0x4504, 0x4505, 0x4510, 0x4511, 0x4514, 0x4515,
        0x4540, 0x4541, 0x4544, 0x4545, 0x4550, 0x4551, 0x4554, 0x4555,
        0x5000, 0x5001, 0x5004, 0x5005, 0x5010, 0x5011, 0x5014, 0x5015,
        0x5040, 0x5041, 0x5044, 0x5045, 0x5050, 0x5051, 0x5054, 0x5055,
        0x5100, 0x5101, 0x5104, 0x5105, 0x5110, 0x5111, 0x5114, 0x5115,
        0x5140, 0x5141, 0x5144, 0x5145, 0x5150, 0x5151, 0x5154, 0x5155,
        0x5400, 0x5401, 0x5404, 0x5405, 0x5410, 0x5411, 0x5414, 0x5415,
        0x5440, 0x5441, 0x5444, 0x5445, 0x5450, 0x5451, 0x5454, 0x5455,
        0x5500, 0x5501, 0x5504, 0x5505, 0x5510, 0x5511, 0x5514, 0x5515,
        0x5540, 0x5541, 0x5544, 0x5545, 0x5550, 0x5551, 0x5554, 0x5555
    };

    /*
     * This expands 7 bit indices into 21 bit contents (high bit 18), by inserting 0s between bits.
     */
    private static final int[] INTERLEAVE3_TABLE = new  int[]
    {
        0x00000, 0x00001, 0x00008, 0x00009, 0x00040, 0x00041, 0x00048, 0x00049,
        0x00200, 0x00201, 0x00208, 0x00209, 0x00240, 0x00241, 0x00248, 0x00249,
        0x01000, 0x01001, 0x01008, 0x01009, 0x01040, 0x01041, 0x01048, 0x01049,
        0x01200, 0x01201, 0x01208, 0x01209, 0x01240, 0x01241, 0x01248, 0x01249,
        0x08000, 0x08001, 0x08008, 0x08009, 0x08040, 0x08041, 0x08048, 0x08049,
        0x08200, 0x08201, 0x08208, 0x08209, 0x08240, 0x08241, 0x08248, 0x08249,
        0x09000, 0x09001, 0x09008, 0x09009, 0x09040, 0x09041, 0x09048, 0x09049,
        0x09200, 0x09201, 0x09208, 0x09209, 0x09240, 0x09241, 0x09248, 0x09249,
        0x40000, 0x40001, 0x40008, 0x40009, 0x40040, 0x40041, 0x40048, 0x40049,
        0x40200, 0x40201, 0x40208, 0x40209, 0x40240, 0x40241, 0x40248, 0x40249,
        0x41000, 0x41001, 0x41008, 0x41009, 0x41040, 0x41041, 0x41048, 0x41049,
        0x41200, 0x41201, 0x41208, 0x41209, 0x41240, 0x41241, 0x41248, 0x41249,
        0x48000, 0x48001, 0x48008, 0x48009, 0x48040, 0x48041, 0x48048, 0x48049,
        0x48200, 0x48201, 0x48208, 0x48209, 0x48240, 0x48241, 0x48248, 0x48249,
        0x49000, 0x49001, 0x49008, 0x49009, 0x49040, 0x49041, 0x49048, 0x49049,
        0x49200, 0x49201, 0x49208, 0x49209, 0x49240, 0x49241, 0x49248, 0x49249
    };

    /*
     * This expands 8 bit indices into 32 bit contents (high bit 28), by inserting 0s between bits.
     */
    private static final int[] INTERLEAVE4_TABLE = new int[]
    {
        0x00000000, 0x00000001, 0x00000010, 0x00000011, 0x00000100, 0x00000101, 0x00000110, 0x00000111,
        0x00001000, 0x00001001, 0x00001010, 0x00001011, 0x00001100, 0x00001101, 0x00001110, 0x00001111,
        0x00010000, 0x00010001, 0x00010010, 0x00010011, 0x00010100, 0x00010101, 0x00010110, 0x00010111,
        0x00011000, 0x00011001, 0x00011010, 0x00011011, 0x00011100, 0x00011101, 0x00011110, 0x00011111,
        0x00100000, 0x00100001, 0x00100010, 0x00100011, 0x00100100, 0x00100101, 0x00100110, 0x00100111,
        0x00101000, 0x00101001, 0x00101010, 0x00101011, 0x00101100, 0x00101101, 0x00101110, 0x00101111,
        0x00110000, 0x00110001, 0x00110010, 0x00110011, 0x00110100, 0x00110101, 0x00110110, 0x00110111,
        0x00111000, 0x00111001, 0x00111010, 0x00111011, 0x00111100, 0x00111101, 0x00111110, 0x00111111,
        0x01000000, 0x01000001, 0x01000010, 0x01000011, 0x01000100, 0x01000101, 0x01000110, 0x01000111,
        0x01001000, 0x01001001, 0x01001010, 0x01001011, 0x01001100, 0x01001101, 0x01001110, 0x01001111,
        0x01010000, 0x01010001, 0x01010010, 0x01010011, 0x01010100, 0x01010101, 0x01010110, 0x01010111,
        0x01011000, 0x01011001, 0x01011010, 0x01011011, 0x01011100, 0x01011101, 0x01011110, 0x01011111,
        0x01100000, 0x01100001, 0x01100010, 0x01100011, 0x01100100, 0x01100101, 0x01100110, 0x01100111,
        0x01101000, 0x01101001, 0x01101010, 0x01101011, 0x01101100, 0x01101101, 0x01101110, 0x01101111,
        0x01110000, 0x01110001, 0x01110010, 0x01110011, 0x01110100, 0x01110101, 0x01110110, 0x01110111,
        0x01111000, 0x01111001, 0x01111010, 0x01111011, 0x01111100, 0x01111101, 0x01111110, 0x01111111,
        0x10000000, 0x10000001, 0x10000010, 0x10000011, 0x10000100, 0x10000101, 0x10000110, 0x10000111,
        0x10001000, 0x10001001, 0x10001010, 0x10001011, 0x10001100, 0x10001101, 0x10001110, 0x10001111,
        0x10010000, 0x10010001, 0x10010010, 0x10010011, 0x10010100, 0x10010101, 0x10010110, 0x10010111,
        0x10011000, 0x10011001, 0x10011010, 0x10011011, 0x10011100, 0x10011101, 0x10011110, 0x10011111,
        0x10100000, 0x10100001, 0x10100010, 0x10100011, 0x10100100, 0x10100101, 0x10100110, 0x10100111,
        0x10101000, 0x10101001, 0x10101010, 0x10101011, 0x10101100, 0x10101101, 0x10101110, 0x10101111,
        0x10110000, 0x10110001, 0x10110010, 0x10110011, 0x10110100, 0x10110101, 0x10110110, 0x10110111,
        0x10111000, 0x10111001, 0x10111010, 0x10111011, 0x10111100, 0x10111101, 0x10111110, 0x10111111,
        0x11000000, 0x11000001, 0x11000010, 0x11000011, 0x11000100, 0x11000101, 0x11000110, 0x11000111,
        0x11001000, 0x11001001, 0x11001010, 0x11001011, 0x11001100, 0x11001101, 0x11001110, 0x11001111,
        0x11010000, 0x11010001, 0x11010010, 0x11010011, 0x11010100, 0x11010101, 0x11010110, 0x11010111,
        0x11011000, 0x11011001, 0x11011010, 0x11011011, 0x11011100, 0x11011101, 0x11011110, 0x11011111,
        0x11100000, 0x11100001, 0x11100010, 0x11100011, 0x11100100, 0x11100101, 0x11100110, 0x11100111,
        0x11101000, 0x11101001, 0x11101010, 0x11101011, 0x11101100, 0x11101101, 0x11101110, 0x11101111,
        0x11110000, 0x11110001, 0x11110010, 0x11110011, 0x11110100, 0x11110101, 0x11110110, 0x11110111,
        0x11111000, 0x11111001, 0x11111010, 0x11111011, 0x11111100, 0x11111101, 0x11111110, 0x11111111
    };

    /*
     * This expands 7 bit indices into 35 bit contents (high bit 30), by inserting 0s between bits.
     */
    private static final int[] INTERLEAVE5_TABLE = new int[] {
        0x00000000, 0x00000001, 0x00000020, 0x00000021, 0x00000400, 0x00000401, 0x00000420, 0x00000421,
        0x00008000, 0x00008001, 0x00008020, 0x00008021, 0x00008400, 0x00008401, 0x00008420, 0x00008421,
        0x00100000, 0x00100001, 0x00100020, 0x00100021, 0x00100400, 0x00100401, 0x00100420, 0x00100421,
        0x00108000, 0x00108001, 0x00108020, 0x00108021, 0x00108400, 0x00108401, 0x00108420, 0x00108421,
        0x02000000, 0x02000001, 0x02000020, 0x02000021, 0x02000400, 0x02000401, 0x02000420, 0x02000421,
        0x02008000, 0x02008001, 0x02008020, 0x02008021, 0x02008400, 0x02008401, 0x02008420, 0x02008421,
        0x02100000, 0x02100001, 0x02100020, 0x02100021, 0x02100400, 0x02100401, 0x02100420, 0x02100421,
        0x02108000, 0x02108001, 0x02108020, 0x02108021, 0x02108400, 0x02108401, 0x02108420, 0x02108421,
        0x40000000, 0x40000001, 0x40000020, 0x40000021, 0x40000400, 0x40000401, 0x40000420, 0x40000421,
        0x40008000, 0x40008001, 0x40008020, 0x40008021, 0x40008400, 0x40008401, 0x40008420, 0x40008421,
        0x40100000, 0x40100001, 0x40100020, 0x40100021, 0x40100400, 0x40100401, 0x40100420, 0x40100421,
        0x40108000, 0x40108001, 0x40108020, 0x40108021, 0x40108400, 0x40108401, 0x40108420, 0x40108421,
        0x42000000, 0x42000001, 0x42000020, 0x42000021, 0x42000400, 0x42000401, 0x42000420, 0x42000421,
        0x42008000, 0x42008001, 0x42008020, 0x42008021, 0x42008400, 0x42008401, 0x42008420, 0x42008421,
        0x42100000, 0x42100001, 0x42100020, 0x42100021, 0x42100400, 0x42100401, 0x42100420, 0x42100421,
        0x42108000, 0x42108001, 0x42108020, 0x42108021, 0x42108400, 0x42108401, 0x42108420, 0x42108421
    };

    /*
     * This expands 9 bit indices into 63 bit (long) contents (high bit 56), by inserting 0s between bits.
     */
    private static final long[] INTERLEAVE7_TABLE = new long[]
    {
        0x0000000000000000L, 0x0000000000000001L, 0x0000000000000080L, 0x0000000000000081L,
        0x0000000000004000L, 0x0000000000004001L, 0x0000000000004080L, 0x0000000000004081L,
        0x0000000000200000L, 0x0000000000200001L, 0x0000000000200080L, 0x0000000000200081L,
        0x0000000000204000L, 0x0000000000204001L, 0x0000000000204080L, 0x0000000000204081L,
        0x0000000010000000L, 0x0000000010000001L, 0x0000000010000080L, 0x0000000010000081L,
        0x0000000010004000L, 0x0000000010004001L, 0x0000000010004080L, 0x0000000010004081L,
        0x0000000010200000L, 0x0000000010200001L, 0x0000000010200080L, 0x0000000010200081L,
        0x0000000010204000L, 0x0000000010204001L, 0x0000000010204080L, 0x0000000010204081L,
        0x0000000800000000L, 0x0000000800000001L, 0x0000000800000080L, 0x0000000800000081L,
        0x0000000800004000L, 0x0000000800004001L, 0x0000000800004080L, 0x0000000800004081L,
        0x0000000800200000L, 0x0000000800200001L, 0x0000000800200080L, 0x0000000800200081L,
        0x0000000800204000L, 0x0000000800204001L, 0x0000000800204080L, 0x0000000800204081L,
        0x0000000810000000L, 0x0000000810000001L, 0x0000000810000080L, 0x0000000810000081L,
        0x0000000810004000L, 0x0000000810004001L, 0x0000000810004080L, 0x0000000810004081L,
        0x0000000810200000L, 0x0000000810200001L, 0x0000000810200080L, 0x0000000810200081L,
        0x0000000810204000L, 0x0000000810204001L, 0x0000000810204080L, 0x0000000810204081L,
        0x0000040000000000L, 0x0000040000000001L, 0x0000040000000080L, 0x0000040000000081L,
        0x0000040000004000L, 0x0000040000004001L, 0x0000040000004080L, 0x0000040000004081L,
        0x0000040000200000L, 0x0000040000200001L, 0x0000040000200080L, 0x0000040000200081L,
        0x0000040000204000L, 0x0000040000204001L, 0x0000040000204080L, 0x0000040000204081L,
        0x0000040010000000L, 0x0000040010000001L, 0x0000040010000080L, 0x0000040010000081L,
        0x0000040010004000L, 0x0000040010004001L, 0x0000040010004080L, 0x0000040010004081L,
        0x0000040010200000L, 0x0000040010200001L, 0x0000040010200080L, 0x0000040010200081L,
        0x0000040010204000L, 0x0000040010204001L, 0x0000040010204080L, 0x0000040010204081L,
        0x0000040800000000L, 0x0000040800000001L, 0x0000040800000080L, 0x0000040800000081L,
        0x0000040800004000L, 0x0000040800004001L, 0x0000040800004080L, 0x0000040800004081L,
        0x0000040800200000L, 0x0000040800200001L, 0x0000040800200080L, 0x0000040800200081L,
        0x0000040800204000L, 0x0000040800204001L, 0x0000040800204080L, 0x0000040800204081L,
        0x0000040810000000L, 0x0000040810000001L, 0x0000040810000080L, 0x0000040810000081L,
        0x0000040810004000L, 0x0000040810004001L, 0x0000040810004080L, 0x0000040810004081L,
        0x0000040810200000L, 0x0000040810200001L, 0x0000040810200080L, 0x0000040810200081L,
        0x0000040810204000L, 0x0000040810204001L, 0x0000040810204080L, 0x0000040810204081L,
        0x0002000000000000L, 0x0002000000000001L, 0x0002000000000080L, 0x0002000000000081L,
        0x0002000000004000L, 0x0002000000004001L, 0x0002000000004080L, 0x0002000000004081L,
        0x0002000000200000L, 0x0002000000200001L, 0x0002000000200080L, 0x0002000000200081L,
        0x0002000000204000L, 0x0002000000204001L, 0x0002000000204080L, 0x0002000000204081L,
        0x0002000010000000L, 0x0002000010000001L, 0x0002000010000080L, 0x0002000010000081L,
        0x0002000010004000L, 0x0002000010004001L, 0x0002000010004080L, 0x0002000010004081L,
        0x0002000010200000L, 0x0002000010200001L, 0x0002000010200080L, 0x0002000010200081L,
        0x0002000010204000L, 0x0002000010204001L, 0x0002000010204080L, 0x0002000010204081L,
        0x0002000800000000L, 0x0002000800000001L, 0x0002000800000080L, 0x0002000800000081L,
        0x0002000800004000L, 0x0002000800004001L, 0x0002000800004080L, 0x0002000800004081L,
        0x0002000800200000L, 0x0002000800200001L, 0x0002000800200080L, 0x0002000800200081L,
        0x0002000800204000L, 0x0002000800204001L, 0x0002000800204080L, 0x0002000800204081L,
        0x0002000810000000L, 0x0002000810000001L, 0x0002000810000080L, 0x0002000810000081L,
        0x0002000810004000L, 0x0002000810004001L, 0x0002000810004080L, 0x0002000810004081L,
        0x0002000810200000L, 0x0002000810200001L, 0x0002000810200080L, 0x0002000810200081L,
        0x0002000810204000L, 0x0002000810204001L, 0x0002000810204080L, 0x0002000810204081L,
        0x0002040000000000L, 0x0002040000000001L, 0x0002040000000080L, 0x0002040000000081L,
        0x0002040000004000L, 0x0002040000004001L, 0x0002040000004080L, 0x0002040000004081L,
        0x0002040000200000L, 0x0002040000200001L, 0x0002040000200080L, 0x0002040000200081L,
        0x0002040000204000L, 0x0002040000204001L, 0x0002040000204080L, 0x0002040000204081L,
        0x0002040010000000L, 0x0002040010000001L, 0x0002040010000080L, 0x0002040010000081L,
        0x0002040010004000L, 0x0002040010004001L, 0x0002040010004080L, 0x0002040010004081L,
        0x0002040010200000L, 0x0002040010200001L, 0x0002040010200080L, 0x0002040010200081L,
        0x0002040010204000L, 0x0002040010204001L, 0x0002040010204080L, 0x0002040010204081L,
        0x0002040800000000L, 0x0002040800000001L, 0x0002040800000080L, 0x0002040800000081L,
        0x0002040800004000L, 0x0002040800004001L, 0x0002040800004080L, 0x0002040800004081L,
        0x0002040800200000L, 0x0002040800200001L, 0x0002040800200080L, 0x0002040800200081L,
        0x0002040800204000L, 0x0002040800204001L, 0x0002040800204080L, 0x0002040800204081L,
        0x0002040810000000L, 0x0002040810000001L, 0x0002040810000080L, 0x0002040810000081L,
        0x0002040810004000L, 0x0002040810004001L, 0x0002040810004080L, 0x0002040810004081L,
        0x0002040810200000L, 0x0002040810200001L, 0x0002040810200080L, 0x0002040810200081L,
        0x0002040810204000L, 0x0002040810204001L, 0x0002040810204080L, 0x0002040810204081L,
        0x0100000000000000L, 0x0100000000000001L, 0x0100000000000080L, 0x0100000000000081L,
        0x0100000000004000L, 0x0100000000004001L, 0x0100000000004080L, 0x0100000000004081L,
        0x0100000000200000L, 0x0100000000200001L, 0x0100000000200080L, 0x0100000000200081L,
        0x0100000000204000L, 0x0100000000204001L, 0x0100000000204080L, 0x0100000000204081L,
        0x0100000010000000L, 0x0100000010000001L, 0x0100000010000080L, 0x0100000010000081L,
        0x0100000010004000L, 0x0100000010004001L, 0x0100000010004080L, 0x0100000010004081L,
        0x0100000010200000L, 0x0100000010200001L, 0x0100000010200080L, 0x0100000010200081L,
        0x0100000010204000L, 0x0100000010204001L, 0x0100000010204080L, 0x0100000010204081L,
        0x0100000800000000L, 0x0100000800000001L, 0x0100000800000080L, 0x0100000800000081L,
        0x0100000800004000L, 0x0100000800004001L, 0x0100000800004080L, 0x0100000800004081L,
        0x0100000800200000L, 0x0100000800200001L, 0x0100000800200080L, 0x0100000800200081L,
        0x0100000800204000L, 0x0100000800204001L, 0x0100000800204080L, 0x0100000800204081L,
        0x0100000810000000L, 0x0100000810000001L, 0x0100000810000080L, 0x0100000810000081L,
        0x0100000810004000L, 0x0100000810004001L, 0x0100000810004080L, 0x0100000810004081L,
        0x0100000810200000L, 0x0100000810200001L, 0x0100000810200080L, 0x0100000810200081L,
        0x0100000810204000L, 0x0100000810204001L, 0x0100000810204080L, 0x0100000810204081L,
        0x0100040000000000L, 0x0100040000000001L, 0x0100040000000080L, 0x0100040000000081L,
        0x0100040000004000L, 0x0100040000004001L, 0x0100040000004080L, 0x0100040000004081L,
        0x0100040000200000L, 0x0100040000200001L, 0x0100040000200080L, 0x0100040000200081L,
        0x0100040000204000L, 0x0100040000204001L, 0x0100040000204080L, 0x0100040000204081L,
        0x0100040010000000L, 0x0100040010000001L, 0x0100040010000080L, 0x0100040010000081L,
        0x0100040010004000L, 0x0100040010004001L, 0x0100040010004080L, 0x0100040010004081L,
        0x0100040010200000L, 0x0100040010200001L, 0x0100040010200080L, 0x0100040010200081L,
        0x0100040010204000L, 0x0100040010204001L, 0x0100040010204080L, 0x0100040010204081L,
        0x0100040800000000L, 0x0100040800000001L, 0x0100040800000080L, 0x0100040800000081L,
        0x0100040800004000L, 0x0100040800004001L, 0x0100040800004080L, 0x0100040800004081L,
        0x0100040800200000L, 0x0100040800200001L, 0x0100040800200080L, 0x0100040800200081L,
        0x0100040800204000L, 0x0100040800204001L, 0x0100040800204080L, 0x0100040800204081L,
        0x0100040810000000L, 0x0100040810000001L, 0x0100040810000080L, 0x0100040810000081L,
        0x0100040810004000L, 0x0100040810004001L, 0x0100040810004080L, 0x0100040810004081L,
        0x0100040810200000L, 0x0100040810200001L, 0x0100040810200080L, 0x0100040810200081L,
        0x0100040810204000L, 0x0100040810204001L, 0x0100040810204080L, 0x0100040810204081L,
        0x0102000000000000L, 0x0102000000000001L, 0x0102000000000080L, 0x0102000000000081L,
        0x0102000000004000L, 0x0102000000004001L, 0x0102000000004080L, 0x0102000000004081L,
        0x0102000000200000L, 0x0102000000200001L, 0x0102000000200080L, 0x0102000000200081L,
        0x0102000000204000L, 0x0102000000204001L, 0x0102000000204080L, 0x0102000000204081L,
        0x0102000010000000L, 0x0102000010000001L, 0x0102000010000080L, 0x0102000010000081L,
        0x0102000010004000L, 0x0102000010004001L, 0x0102000010004080L, 0x0102000010004081L,
        0x0102000010200000L, 0x0102000010200001L, 0x0102000010200080L, 0x0102000010200081L,
        0x0102000010204000L, 0x0102000010204001L, 0x0102000010204080L, 0x0102000010204081L,
        0x0102000800000000L, 0x0102000800000001L, 0x0102000800000080L, 0x0102000800000081L,
        0x0102000800004000L, 0x0102000800004001L, 0x0102000800004080L, 0x0102000800004081L,
        0x0102000800200000L, 0x0102000800200001L, 0x0102000800200080L, 0x0102000800200081L,
        0x0102000800204000L, 0x0102000800204001L, 0x0102000800204080L, 0x0102000800204081L,
        0x0102000810000000L, 0x0102000810000001L, 0x0102000810000080L, 0x0102000810000081L,
        0x0102000810004000L, 0x0102000810004001L, 0x0102000810004080L, 0x0102000810004081L,
        0x0102000810200000L, 0x0102000810200001L, 0x0102000810200080L, 0x0102000810200081L,
        0x0102000810204000L, 0x0102000810204001L, 0x0102000810204080L, 0x0102000810204081L,
        0x0102040000000000L, 0x0102040000000001L, 0x0102040000000080L, 0x0102040000000081L,
        0x0102040000004000L, 0x0102040000004001L, 0x0102040000004080L, 0x0102040000004081L,
        0x0102040000200000L, 0x0102040000200001L, 0x0102040000200080L, 0x0102040000200081L,
        0x0102040000204000L, 0x0102040000204001L, 0x0102040000204080L, 0x0102040000204081L,
        0x0102040010000000L, 0x0102040010000001L, 0x0102040010000080L, 0x0102040010000081L,
        0x0102040010004000L, 0x0102040010004001L, 0x0102040010004080L, 0x0102040010004081L,
        0x0102040010200000L, 0x0102040010200001L, 0x0102040010200080L, 0x0102040010200081L,
        0x0102040010204000L, 0x0102040010204001L, 0x0102040010204080L, 0x0102040010204081L,
        0x0102040800000000L, 0x0102040800000001L, 0x0102040800000080L, 0x0102040800000081L,
        0x0102040800004000L, 0x0102040800004001L, 0x0102040800004080L, 0x0102040800004081L,
        0x0102040800200000L, 0x0102040800200001L, 0x0102040800200080L, 0x0102040800200081L,
        0x0102040800204000L, 0x0102040800204001L, 0x0102040800204080L, 0x0102040800204081L,
        0x0102040810000000L, 0x0102040810000001L, 0x0102040810000080L, 0x0102040810000081L,
        0x0102040810004000L, 0x0102040810004001L, 0x0102040810004080L, 0x0102040810004081L,
        0x0102040810200000L, 0x0102040810200001L, 0x0102040810200080L, 0x0102040810200081L,
        0x0102040810204000L, 0x0102040810204001L, 0x0102040810204080L, 0x0102040810204081L
    };

    // For toString(); must have length 64
    private static final String ZEROES = "0000000000000000000000000000000000000000000000000000000000000000";

    final static byte[] bitLengths =
    {
        0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8
    };

    // TODO make m fixed for the LongArray, and hence compute T once and for all

    private long[] m_ints;

    public LongArray(int intLen)
    {
        m_ints = new long[intLen];
    }

    public LongArray(long[] ints)
    {
        m_ints = ints;
    }

    public LongArray(long[] ints, int off, int len)
    {
        if (off == 0 && len == ints.length)
        {
            m_ints = ints;
        }
        else
        {
            m_ints = new long[len];
            System.arraycopy(ints, off, m_ints, 0, len);
        }
    }

    public LongArray(BigInteger bigInt)
    {
        if (bigInt == null || bigInt.signum() < 0)
        {
            throw new IllegalArgumentException("invalid F2m field value");
        }

        if (bigInt.signum() == 0)
        {
            m_ints = new long[] { 0L };
            return;
        }

        byte[] barr = bigInt.toByteArray();
        int barrLen = barr.length;
        int barrStart = 0;
        if (barr[0] == 0)
        {
            // First byte is 0 to enforce highest (=sign) bit is zero.
            // In this case ignore barr[0].
            barrLen--;
            barrStart = 1;
        }
        int intLen = (barrLen + 7) / 8;
        m_ints = new long[intLen];

        int iarrJ = intLen - 1;
        int rem = barrLen % 8 + barrStart;
        long temp = 0;
        int barrI = barrStart;
        if (barrStart < rem)
        {
            for (; barrI < rem; barrI++)
            {
                temp <<= 8;
                int barrBarrI = barr[barrI] & 0xFF;
                temp |= barrBarrI;
            }
            m_ints[iarrJ--] = temp;
        }

        for (; iarrJ >= 0; iarrJ--)
        {
            temp = 0;
            for (int i = 0; i < 8; i++)
            {
                temp <<= 8;
                int barrBarrI = barr[barrI++] & 0xFF;
                temp |= barrBarrI;
            }
            m_ints[iarrJ] = temp;
        }
    }

    public boolean isOne()
    {
        long[] a = m_ints;
        if (a[0] != 1L)
        {
            return false;
        }
        for (int i = 1; i < a.length; ++i)
        {
            if (a[i] != 0L)
            {
                return false;
            }
        }
        return true;
    }

    public boolean isZero()
    {
        long[] a = m_ints;
        for (int i = 0; i < a.length; ++i)
        {
            if (a[i] != 0L)
            {
                return false;
            }
        }
        return true;
    }

    public int getUsedLength()
    {
        return getUsedLengthFrom(m_ints.length);
    }

    public int getUsedLengthFrom(int from)
    {
        long[] a = m_ints;
        from = Math.min(from, a.length);

        if (from < 1)
        {
            return 0;
        }

        // Check if first element will act as sentinel
        if (a[0] != 0)
        {
            while (a[--from] == 0)
            {
            }
            return from + 1;
        }

        do
        {
            if (a[--from] != 0)
            {
                return from + 1;
            }
        }
        while (from > 0);

        return 0;
    }

    public int degree()
    {
        int i = m_ints.length;
        long w;
        do
        {
            if (i == 0)
            {
                return 0;
            }
            w = m_ints[--i];
        }
        while (w == 0);

        return (i << 6) + bitLength(w);
    }

    private int degreeFrom(int limit)
    {
        int i = (limit + 62) >>> 6;
        long w;
        do
        {
            if (i == 0)
            {
                return 0;
            }
            w = m_ints[--i];
        }
        while (w == 0);

        return (i << 6) + bitLength(w);
    }

//    private int lowestCoefficient()
//    {
//        for (int i = 0; i < m_ints.length; ++i)
//        {
//            long mi = m_ints[i];
//            if (mi != 0)
//            {
//                int j = 0;
//                while ((mi & 0xFFL) == 0)
//                {
//                    j += 8;
//                    mi >>>= 8;
//                }
//                while ((mi & 1L) == 0)
//                {
//                    ++j;
//                    mi >>>= 1;
//                }
//                return (i << 6) + j;
//            }
//        }
//        return -1;
//    }

    private static int bitLength(long w)
    {
        int u = (int)(w >>> 32), b;
        if (u == 0)
        {
            u = (int)w;
            b = 0;
        }
        else
        {
            b = 32;
        }

        int t = u >>> 16, k;
        if (t == 0)
        {
            t = u >>> 8;
            k = (t == 0) ? bitLengths[u] : 8 + bitLengths[t];
        }
        else
        {
            int v = t >>> 8;
            k = (v == 0) ? 16 + bitLengths[t] : 24 + bitLengths[v];
        }

        return b + k;
    }

    private long[] resizedInts(int newLen)
    {
        long[] newInts = new long[newLen];
        System.arraycopy(m_ints, 0, newInts, 0, Math.min(m_ints.length, newLen));
        return newInts;
    }

    public BigInteger toBigInteger()
    {
        int usedLen = getUsedLength();
        if (usedLen == 0)
        {
            return ECConstants.ZERO;
        }

        long highestInt = m_ints[usedLen - 1];
        byte[] temp = new byte[8];
        int barrI = 0;
        boolean trailingZeroBytesDone = false;
        for (int j = 7; j >= 0; j--)
        {
            byte thisByte = (byte)(highestInt >>> (8 * j));
            if (trailingZeroBytesDone || (thisByte != 0))
            {
                trailingZeroBytesDone = true;
                temp[barrI++] = thisByte;
            }
        }

        int barrLen = 8 * (usedLen - 1) + barrI;
        byte[] barr = new byte[barrLen];
        for (int j = 0; j < barrI; j++)
        {
            barr[j] = temp[j];
        }
        // Highest value int is done now

        for (int iarrJ = usedLen - 2; iarrJ >= 0; iarrJ--)
        {
            long mi = m_ints[iarrJ];
            for (int j = 7; j >= 0; j--)
            {
                barr[barrI++] = (byte)(mi >>> (8 * j));
            }
        }
        return new BigInteger(1, barr);
    }

//    private static long shiftUp(long[] x, int xOff, int count)
//    {
//        long prev = 0;
//        for (int i = 0; i < count; ++i)
//        {
//            long next = x[xOff + i];
//            x[xOff + i] = (next << 1) | prev;
//            prev = next >>> 63;
//        }
//        return prev;
//    }

    private static long shiftUp(long[] x, int xOff, int count, int shift)
    {
        int shiftInv = 64 - shift;
        long prev = 0;
        for (int i = 0; i < count; ++i)
        {
            long next = x[xOff + i];
            x[xOff + i] = (next << shift) | prev;
            prev = next >>> shiftInv;
        }
        return prev;
    }

    private static long shiftUp(long[] x, int xOff, long[] z, int zOff, int count, int shift)
    {
        int shiftInv = 64 - shift;
        long prev = 0;
        for (int i = 0; i < count; ++i)
        {
            long next = x[xOff + i];
            z[zOff + i] = (next << shift) | prev;
            prev = next >>> shiftInv;
        }
        return prev;
    }

    public LongArray addOne()
    {
        if (m_ints.length == 0)
        {
            return new LongArray(new long[]{ 1L });
        }

        int resultLen = Math.max(1, getUsedLength());
        long[] ints = resizedInts(resultLen);
        ints[0] ^= 1L;
        return new LongArray(ints);
    }

//    private void addShiftedByBits(LongArray other, int bits)
//    {
//        int words = bits >>> 6;
//        int shift = bits & 0x3F;
//
//        if (shift == 0)
//        {
//            addShiftedByWords(other, words);
//            return;
//        }
//
//        int otherUsedLen = other.getUsedLength();
//        if (otherUsedLen == 0)
//        {
//            return;
//        }
//
//        int minLen = otherUsedLen + words + 1;
//        if (minLen > m_ints.length)
//        {
//            m_ints = resizedInts(minLen);
//        }
//
//        long carry = addShiftedByBits(m_ints, words, other.m_ints, 0, otherUsedLen, shift);
//        m_ints[otherUsedLen + words] ^= carry;
//    }

    private void addShiftedByBitsSafe(LongArray other, int otherDegree, int bits)
    {
        int otherLen = (otherDegree + 63) >>> 6;

        int words = bits >>> 6;
        int shift = bits & 0x3F;

        if (shift == 0)
        {
            add(m_ints, words, other.m_ints, 0, otherLen);
            return;
        }

        long carry = addShiftedUp(m_ints, words, other.m_ints, 0, otherLen, shift);
        if (carry != 0L)
        {
            m_ints[otherLen + words] ^= carry;
        }
    }

    private static long addShiftedUp(long[] x, int xOff, long[] y, int yOff, int count, int shift)
    {
        int shiftInv = 64 - shift;
        long prev = 0;
        for (int i = 0; i < count; ++i)
        {
            long next = y[yOff + i];
            x[xOff + i] ^= (next << shift) | prev;
            prev = next >>> shiftInv;
        }
        return prev;
    }

    private static long addShiftedDown(long[] x, int xOff, long[] y, int yOff, int count, int shift)
    {
        int shiftInv = 64 - shift;
        long prev = 0;
        int i = count;
        while (--i >= 0)
        {
            long next = y[yOff + i];
            x[xOff + i] ^= (next >>> shift) | prev;
            prev = next << shiftInv;
        }
        return prev;
    }

    public void addShiftedByWords(LongArray other, int words)
    {
        int otherUsedLen = other.getUsedLength();
        if (otherUsedLen == 0)
        {
            return;
        }

        int minLen = otherUsedLen + words;
        if (minLen > m_ints.length)
        {
            m_ints = resizedInts(minLen);
        }

        add(m_ints, words, other.m_ints, 0, otherUsedLen);
    }

    private static void add(long[] x, int xOff, long[] y, int yOff, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            x[xOff + i] ^= y[yOff + i];
        }
    }

    private static void add(long[] x, int xOff, long[] y, int yOff, long[] z, int zOff, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            z[zOff + i] = x[xOff + i] ^ y[yOff + i];
        }
    }

    private static void addBoth(long[] x, int xOff, long[] y1, int y1Off, long[] y2, int y2Off, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            x[xOff + i] ^= y1[y1Off + i] ^ y2[y2Off + i];
        }
    }

    private static void distribute(long[] x, int src, int dst1, int dst2, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            long v = x[src + i];
            x[dst1 + i] ^= v;
            x[dst2 + i] ^= v;
        }
    }

    public int getLength()
    {
        return m_ints.length;
    }

    private static void flipWord(long[] buf, int off, int bit, long word)
    {
        int n = off + (bit >>> 6);
        int shift = bit & 0x3F;
        if (shift == 0)
        {
            buf[n] ^= word;
        }
        else
        {
            buf[n] ^= word << shift;
            word >>>= (64 - shift);
            if (word != 0)
            {
                buf[++n] ^= word;
            }
        }
    }

//    private static long getWord(long[] buf, int off, int len, int bit)
//    {
//        int n = off + (bit >>> 6);
//        int shift = bit & 0x3F;
//        if (shift == 0)
//        {
//            return buf[n];
//        }
//        long result = buf[n] >>> shift;
//        if (++n < len)
//        {
//            result |= buf[n] << (64 - shift);
//        }
//        return result;
//    }

    public boolean testBitZero()
    {
        return m_ints.length > 0 && (m_ints[0] & 1L) != 0;
    }

    private static boolean testBit(long[] buf, int off, int n)
    {
        // theInt = n / 64
        int theInt = n >>> 6;
        // theBit = n % 64
        int theBit = n & 0x3F;
        long tester = 1L << theBit;
        return (buf[off + theInt] & tester) != 0;
    }

    private static void flipBit(long[] buf, int off, int n)
    {
        // theInt = n / 64
        int theInt = n >>> 6;
        // theBit = n % 64
        int theBit = n & 0x3F;
        long flipper = 1L << theBit;
        buf[off + theInt] ^= flipper;
    }

//    private static void setBit(long[] buf, int off, int n)
//    {
//        // theInt = n / 64
//        int theInt = n >>> 6;
//        // theBit = n % 64
//        int theBit = n & 0x3F;
//        long setter = 1L << theBit;
//        buf[off + theInt] |= setter;
//    }
//
//    private static void clearBit(long[] buf, int off, int n)
//    {
//        // theInt = n / 64
//        int theInt = n >>> 6;
//        // theBit = n % 64
//        int theBit = n & 0x3F;
//        long setter = 1L << theBit;
//        buf[off + theInt] &= ~setter;
//    }

    private static void multiplyWord(long a, long[] b, int bLen, long[] c, int cOff)
    {
        if ((a & 1L) != 0L)
        {
            add(c, cOff, b, 0, bLen);
        }
        int k = 1;
        while ((a >>>= 1) != 0L)
        {
            if ((a & 1L) != 0L)
            {
                long carry = addShiftedUp(c, cOff, b, 0, bLen, k);
                if (carry != 0L)
                {
                    c[cOff + bLen] ^= carry;
                }
            }
            ++k;
        }
    }

    public LongArray modMultiplyLD(LongArray other, int m, int[] ks)
    {
        /*
         * Find out the degree of each argument and handle the zero cases
         */
        int aDeg = degree();
        if (aDeg == 0)
        {
            return this;
        }
        int bDeg = other.degree();
        if (bDeg == 0)
        {
            return other;
        }

        /*
         * Swap if necessary so that A is the smaller argument
         */
        LongArray A = this, B = other;
        if (aDeg > bDeg)
        {
            A = other; B = this;
            int tmp = aDeg; aDeg = bDeg; bDeg = tmp;
        }

        /*
         * Establish the word lengths of the arguments and result
         */
        int aLen = (aDeg + 63) >>> 6;
        int bLen = (bDeg + 63) >>> 6;
        int cLen = (aDeg + bDeg + 62) >>> 6;

        if (aLen == 1)
        {
            long a0 = A.m_ints[0];
            if (a0 == 1L)
            {
                return B;
            }

            /*
             * Fast path for small A, with performance dependent only on the number of set bits
             */
            long[] c0 = new long[cLen];
            multiplyWord(a0, B.m_ints, bLen, c0, 0);

            /*
             * Reduce the raw answer against the reduction coefficients
             */
            return reduceResult(c0, 0, cLen, m, ks);
        }

        /*
         * Determine if B will get bigger during shifting
         */
        int bMax = (bDeg + 7 + 63) >>> 6;

        /*
         * Lookup table for the offset of each B in the tables
         */
        int[] ti = new int[16];

        /*
         * Precompute table of all 4-bit products of B
         */
        long[] T0 = new long[bMax << 4];
        int tOff = bMax;
        ti[1] = tOff;
        System.arraycopy(B.m_ints, 0, T0, tOff, bLen);
        for (int i = 2; i < 16; ++i)
        {
            ti[i] = (tOff += bMax);
            if ((i & 1) == 0)
            {
                shiftUp(T0, tOff >>> 1, T0, tOff, bMax, 1);
            }
            else
            {
                add(T0, bMax, T0, tOff - bMax, T0, tOff, bMax);
            }
        }

        /*
         * Second table with all 4-bit products of B shifted 4 bits
         */
        long[] T1 = new long[T0.length];
        shiftUp(T0, 0, T1, 0, T0.length, 4);
//        shiftUp(T0, bMax, T1, bMax, tOff, 4);

        long[] a = A.m_ints;
        long[] c = new long[cLen];

        int MASK = 0xF;

        /*
         * Lopez-Dahab algorithm
         */

        for (int k = 56; k >= 0; k -= 8)
        {
            for (int j = 1; j < aLen; j += 2)
            {
                int aVal = (int)(a[j] >>> k);
                int u = aVal & MASK;
                int v = (aVal >>> 4) & MASK;
                addBoth(c, j - 1, T0, ti[u], T1, ti[v], bMax);
            }
            shiftUp(c, 0, cLen, 8);
        }

        for (int k = 56; k >= 0; k -= 8)
        {
            for (int j = 0; j < aLen; j += 2)
            {
                int aVal = (int)(a[j] >>> k);
                int u = aVal & MASK;
                int v = (aVal >>> 4) & MASK;
                addBoth(c, j, T0, ti[u], T1, ti[v], bMax);
            }
            if (k > 0)
            {
                shiftUp(c, 0, cLen, 8);
            }
        }

        /*
         * Finally the raw answer is collected, reduce it against the reduction coefficients
         */
        return reduceResult(c, 0, cLen, m, ks);
    }

    public LongArray modMultiply(LongArray other, int m, int[] ks)
    {
        /*
         * Find out the degree of each argument and handle the zero cases
         */
        int aDeg = degree();
        if (aDeg == 0)
        {
            return this;
        }
        int bDeg = other.degree();
        if (bDeg == 0)
        {
            return other;
        }

        /*
         * Swap if necessary so that A is the smaller argument
         */
        LongArray A = this, B = other;
        if (aDeg > bDeg)
        {
            A = other; B = this;
            int tmp = aDeg; aDeg = bDeg; bDeg = tmp;
        }

        /*
         * Establish the word lengths of the arguments and result
         */
        int aLen = (aDeg + 63) >>> 6;
        int bLen = (bDeg + 63) >>> 6;
        int cLen = (aDeg + bDeg + 62) >>> 6;

        if (aLen == 1)
        {
            long a0 = A.m_ints[0];
            if (a0 == 1L)
            {
                return B;
            }

            /*
             * Fast path for small A, with performance dependent only on the number of set bits
             */
            long[] c0 = new long[cLen];
            multiplyWord(a0, B.m_ints, bLen, c0, 0);

            /*
             * Reduce the raw answer against the reduction coefficients
             */
            return reduceResult(c0, 0, cLen, m, ks);
        }

        /*
         * Determine if B will get bigger during shifting
         */
        int bMax = (bDeg + 7 + 63) >>> 6;

        /*
         * Lookup table for the offset of each B in the tables
         */
        int[] ti = new int[16];

        /*
         * Precompute table of all 4-bit products of B
         */
        long[] T0 = new long[bMax << 4];
        int tOff = bMax;
        ti[1] = tOff;
        System.arraycopy(B.m_ints, 0, T0, tOff, bLen);
        for (int i = 2; i < 16; ++i)
        {
            ti[i] = (tOff += bMax);
            if ((i & 1) == 0)
            {
                shiftUp(T0, tOff >>> 1, T0, tOff, bMax, 1);
            }
            else
            {
                add(T0, bMax, T0, tOff - bMax, T0, tOff, bMax);
            }
        }

        /*
         * Second table with all 4-bit products of B shifted 4 bits
         */
        long[] T1 = new long[T0.length];
        shiftUp(T0, 0, T1, 0, T0.length, 4);
//        shiftUp(T0, bMax, T1, bMax, tOff, 4);

        long[] a = A.m_ints;
        long[] c = new long[cLen << 3];

        int MASK = 0xF;

        /*
         * Lopez-Dahab (Modified) algorithm
         */

        for (int aPos = 0; aPos < aLen; ++aPos)
        {
            long aVal = a[aPos];
            int cOff = aPos;
            for (;;)
            {
                int u = (int)aVal & MASK;
                aVal >>>= 4;
                int v = (int)aVal & MASK;
                addBoth(c, cOff, T0, ti[u], T1, ti[v], bMax);
                aVal >>>= 4;
                if (aVal == 0L)
                {
                    break;
                }
                cOff += cLen;
            }
        }

        {
            int cOff = c.length;
            while ((cOff -= cLen) != 0)
            {
                addShiftedUp(c, cOff - cLen, c, cOff, cLen, 8);
            }
        }

        /*
         * Finally the raw answer is collected, reduce it against the reduction coefficients
         */
        return reduceResult(c, 0, cLen, m, ks);
    }

    public LongArray modMultiplyAlt(LongArray other, int m, int[] ks)
    {
        /*
         * Find out the degree of each argument and handle the zero cases
         */
        int aDeg = degree();
        if (aDeg == 0)
        {
            return this;
        }
        int bDeg = other.degree();
        if (bDeg == 0)
        {
            return other;
        }

        /*
         * Swap if necessary so that A is the smaller argument
         */
        LongArray A = this, B = other;
        if (aDeg > bDeg)
        {
            A = other; B = this;
            int tmp = aDeg; aDeg = bDeg; bDeg = tmp;
        }

        /*
         * Establish the word lengths of the arguments and result
         */
        int aLen = (aDeg + 63) >>> 6;
        int bLen = (bDeg + 63) >>> 6;
        int cLen = (aDeg + bDeg + 62) >>> 6;

        if (aLen == 1)
        {
            long a0 = A.m_ints[0];
            if (a0 == 1L)
            {
                return B;
            }

            /*
             * Fast path for small A, with performance dependent only on the number of set bits
             */
            long[] c0 = new long[cLen];
            multiplyWord(a0, B.m_ints, bLen, c0, 0);

            /*
             * Reduce the raw answer against the reduction coefficients
             */
            return reduceResult(c0, 0, cLen, m, ks);
        }

        // NOTE: This works, but is slower than width 4 processing
//        if (aLen == 2)
//        {
//            /*
//             * Use common-multiplicand optimization to save ~1/4 of the adds
//             */
//            long a1 = A.m_ints[0], a2 = A.m_ints[1];
//            long aa = a1 & a2; a1 ^= aa; a2 ^= aa;
//
//            long[] b = B.m_ints;
//            long[] c = new long[cLen];
//            multiplyWord(aa, b, bLen, c, 1);
//            add(c, 0, c, 1, cLen - 1);
//            multiplyWord(a1, b, bLen, c, 0);
//            multiplyWord(a2, b, bLen, c, 1);
//
//            /*
//             * Reduce the raw answer against the reduction coefficients
//             */
//            return reduceResult(c, 0, cLen, m, ks);
//        }

        /*
         * Determine the parameters of the interleaved window algorithm: the 'width' in bits to
         * process together, the number of evaluation 'positions' implied by that width, and the
         * 'top' position at which the regular window algorithm stops.
         */
        int width, positions, top, banks;

        // NOTE: width 4 is the fastest over the entire range of sizes used in current crypto 
//        width = 1; positions = 64; top = 64; banks = 4;
//        width = 2; positions = 32; top = 64; banks = 4;
//        width = 3; positions = 21; top = 63; banks = 3;
        width = 4; positions = 16; top = 64; banks = 8;
//        width = 5; positions = 13; top = 65; banks = 7;
//        width = 7; positions = 9; top = 63; banks = 9;
//        width = 8; positions = 8; top = 64; banks = 8;

        /*
         * Determine if B will get bigger during shifting
         */
        int shifts = top < 64 ? positions : positions - 1;
        int bMax = (bDeg + shifts + 63) >>> 6;

        int bTotal = bMax * banks, stride = width * banks;

        /*
         * Create a single temporary buffer, with an offset table to find the positions of things in it 
         */
        int[] ci = new int[1 << width];
        int cTotal = aLen;
        {
            ci[0] = cTotal;
            cTotal += bTotal;
            ci[1] = cTotal;
            for (int i = 2; i < ci.length; ++i)
            {
                cTotal += cLen;
                ci[i] = cTotal;
            }
            cTotal += cLen;
        }
        // NOTE: Provide a safe dump for "high zeroes" since we are adding 'bMax' and not 'bLen'
        ++cTotal;

        long[] c = new long[cTotal];

        // Prepare A in interleaved form, according to the chosen width
        interleave(A.m_ints, 0, c, 0, aLen, width);

        // Make a working copy of B, since we will be shifting it
        {
            int bOff = aLen;
            System.arraycopy(B.m_ints, 0, c, bOff, bLen);
            for (int bank = 1; bank < banks; ++bank)
            {
                shiftUp(c, aLen, c, bOff += bMax, bMax, bank);
            }
        }

        /*
         * The main loop analyzes the interleaved windows in A, and for each non-zero window
         * a single word-array XOR is performed to a carefully selected slice of 'c'. The loop is
         * breadth-first, checking the lowest window in each word, then looping again for the
         * next higher window position.
         */
        int MASK = (1 << width) - 1;

        int k = 0;
        for (;;)
        {
            int aPos = 0;
            do
            {
                long aVal = c[aPos] >>> k;
                int bank = 0, bOff = aLen;
                for (;;)
                {
                    int index = (int)(aVal) & MASK;
                    if (index != 0)
                    {
                        /*
                         * Add to a 'c' buffer based on the bit-pattern of 'index'. Since A is in
                         * interleaved form, the bits represent the current B shifted by 0, 'positions',
                         * 'positions' * 2, ..., 'positions' * ('width' - 1)
                         */
                        add(c, aPos + ci[index], c, bOff, bMax);
                    }
                    if (++bank == banks)
                    {
                        break;
                    }
                    bOff += bMax;
                    aVal >>>= width;
                }
            }
            while (++aPos < aLen);

            if ((k += stride) >= top)
            {
                if (k >= 64)
                {
                    break;
                }

                /*
                 * Adjustment for window setups with top == 63, the final bit (if any) is processed
                 * as the top-bit of a window
                 */
                k = 64 - width;
                MASK &= MASK << (top - k);
            }

            /*
             * After each position has been checked for all words of A, B is shifted up 1 place
             */
            shiftUp(c, aLen, bTotal, banks);
        }

        int ciPos = ci.length;
        while (--ciPos > 1)
        {
            if ((ciPos & 1L) == 0L)
            {
                /*
                 * For even numbers, shift contents and add to the half-position
                 */
                addShiftedUp(c, ci[ciPos >>> 1], c, ci[ciPos], cLen, positions);
            }
            else
            {
                /*
                 * For odd numbers, 'distribute' contents to the result and the next-lowest position
                 */
                distribute(c, ci[ciPos], ci[ciPos - 1], ci[1], cLen);
            }
        }

        /*
         * Finally the raw answer is collected, reduce it against the reduction coefficients
         */
        return reduceResult(c, ci[1], cLen, m, ks);
    }

    public LongArray modReduce(int m, int[] ks)
    {
        long[] buf = Arrays.clone(m_ints);
        int rLen = reduceInPlace(buf, 0, buf.length, m, ks);
        return new LongArray(buf, 0, rLen);
    }

    public LongArray multiply(LongArray other, int m, int[] ks)
    {
        /*
         * Find out the degree of each argument and handle the zero cases
         */
        int aDeg = degree();
        if (aDeg == 0)
        {
            return this;
        }
        int bDeg = other.degree();
        if (bDeg == 0)
        {
            return other;
        }

        /*
         * Swap if necessary so that A is the smaller argument
         */
        LongArray A = this, B = other;
        if (aDeg > bDeg)
        {
            A = other; B = this;
            int tmp = aDeg; aDeg = bDeg; bDeg = tmp;
        }

        /*
         * Establish the word lengths of the arguments and result
         */
        int aLen = (aDeg + 63) >>> 6;
        int bLen = (bDeg + 63) >>> 6;
        int cLen = (aDeg + bDeg + 62) >>> 6;

        if (aLen == 1)
        {
            long a0 = A.m_ints[0];
            if (a0 == 1L)
            {
                return B;
            }

            /*
             * Fast path for small A, with performance dependent only on the number of set bits
             */
            long[] c0 = new long[cLen];
            multiplyWord(a0, B.m_ints, bLen, c0, 0);

            /*
             * Reduce the raw answer against the reduction coefficients
             */
//            return reduceResult(c0, 0, cLen, m, ks);
            return new LongArray(c0, 0, cLen);
        }

        /*
         * Determine if B will get bigger during shifting
         */
        int bMax = (bDeg + 7 + 63) >>> 6;

        /*
         * Lookup table for the offset of each B in the tables
         */
        int[] ti = new int[16];

        /*
         * Precompute table of all 4-bit products of B
         */
        long[] T0 = new long[bMax << 4];
        int tOff = bMax;
        ti[1] = tOff;
        System.arraycopy(B.m_ints, 0, T0, tOff, bLen);
        for (int i = 2; i < 16; ++i)
        {
            ti[i] = (tOff += bMax);
            if ((i & 1) == 0)
            {
                shiftUp(T0, tOff >>> 1, T0, tOff, bMax, 1);
            }
            else
            {
                add(T0, bMax, T0, tOff - bMax, T0, tOff, bMax);
            }
        }

        /*
         * Second table with all 4-bit products of B shifted 4 bits
         */
        long[] T1 = new long[T0.length];
        shiftUp(T0, 0, T1, 0, T0.length, 4);
//        shiftUp(T0, bMax, T1, bMax, tOff, 4);

        long[] a = A.m_ints;
        long[] c = new long[cLen << 3];

        int MASK = 0xF;

        /*
         * Lopez-Dahab (Modified) algorithm
         */

        for (int aPos = 0; aPos < aLen; ++aPos)
        {
            long aVal = a[aPos];
            int cOff = aPos;
            for (;;)
            {
                int u = (int)aVal & MASK;
                aVal >>>= 4;
                int v = (int)aVal & MASK;
                addBoth(c, cOff, T0, ti[u], T1, ti[v], bMax);
                aVal >>>= 4;
                if (aVal == 0L)
                {
                    break;
                }
                cOff += cLen;
            }
        }

        {
            int cOff = c.length;
            while ((cOff -= cLen) != 0)
            {
                addShiftedUp(c, cOff - cLen, c, cOff, cLen, 8);
            }
        }

        /*
         * Finally the raw answer is collected, reduce it against the reduction coefficients
         */
//        return reduceResult(c, 0, cLen, m, ks);
        return new LongArray(c, 0, cLen);
    }

    public void reduce(int m, int[] ks)
    {
        long[] buf = m_ints;
        int rLen = reduceInPlace(buf, 0, buf.length, m, ks);
        if (rLen < buf.length)
        {
            m_ints = new long[rLen];
            System.arraycopy(buf, 0, m_ints, 0, rLen);
        }
    }

    private static LongArray reduceResult(long[] buf, int off, int len, int m, int[] ks)
    {
        int rLen = reduceInPlace(buf, off, len, m, ks);
        return new LongArray(buf, off, rLen);
    }

//    private static void deInterleave(long[] x, int xOff, long[] z, int zOff, int count, int rounds)
//    {
//        for (int i = 0; i < count; ++i)
//        {
//            z[zOff + i] = deInterleave(x[zOff + i], rounds);
//        }
//    }
//
//    private static long deInterleave(long x, int rounds)
//    {
//        while (--rounds >= 0)
//        {
//            x = deInterleave32(x & DEINTERLEAVE_MASK) | (deInterleave32((x >>> 1) & DEINTERLEAVE_MASK) << 32);
//        }
//        return x;
//    }
//
//    private static long deInterleave32(long x)
//    {
//        x = (x | (x >>> 1)) & 0x3333333333333333L;
//        x = (x | (x >>> 2)) & 0x0F0F0F0F0F0F0F0FL;
//        x = (x | (x >>> 4)) & 0x00FF00FF00FF00FFL;
//        x = (x | (x >>> 8)) & 0x0000FFFF0000FFFFL;
//        x = (x | (x >>> 16)) & 0x00000000FFFFFFFFL;
//        return x;
//    }

    private static int reduceInPlace(long[] buf, int off, int len, int m, int[] ks)
    {
        int mLen = (m + 63) >>> 6;
        if (len < mLen)
        {
            return len;
        }

        int numBits = Math.min(len << 6, (m << 1) - 1); // TODO use actual degree?
        int excessBits = (len << 6) - numBits;
        while (excessBits >= 64)
        {
            --len;
            excessBits -= 64;
        }

        int kLen = ks.length, kMax = ks[kLen - 1], kNext = kLen > 1 ? ks[kLen - 2] : 0;
        int wordWiseLimit = Math.max(m, kMax + 64);
        int vectorableWords = (excessBits + Math.min(numBits - wordWiseLimit, m - kNext)) >> 6;
        if (vectorableWords > 1)
        {
            int vectorWiseWords = len - vectorableWords;
            reduceVectorWise(buf, off, len, vectorWiseWords, m, ks);
            while (len > vectorWiseWords)
            {
                buf[off + --len] = 0L;
            }
            numBits = vectorWiseWords << 6;
        }

        if (numBits > wordWiseLimit)
        {
            reduceWordWise(buf, off, len, wordWiseLimit, m, ks);
            numBits = wordWiseLimit;
        }

        if (numBits > m)
        {
            reduceBitWise(buf, off, numBits, m, ks);
        }

        return mLen;
    }

    private static void reduceBitWise(long[] buf, int off, int bitlength, int m, int[] ks)
    {
        while (--bitlength >= m)
        {
            if (testBit(buf, off, bitlength))
            {
                reduceBit(buf, off, bitlength, m, ks);
            }
        }
    }

    private static void reduceBit(long[] buf, int off, int bit, int m, int[] ks)
    {
        flipBit(buf, off, bit);
        int n = bit - m;
        int j = ks.length;
        while (--j >= 0)
        {
            flipBit(buf, off, ks[j] + n);
        }
        flipBit(buf, off, n);
    }

    private static void reduceWordWise(long[] buf, int off, int len, int toBit, int m, int[] ks)
    {
        int toPos = toBit >>> 6;

        while (--len > toPos)
        {
            long word = buf[off + len];
            if (word != 0)
            {
                buf[off + len] = 0;
                reduceWord(buf, off, (len << 6), word, m, ks);
            }
        }

        {
            int partial = toBit & 0x3F;
            long word = buf[off + toPos] >>> partial;
            if (word != 0)
            {
                buf[off + toPos] ^= word << partial;
                reduceWord(buf, off, toBit, word, m, ks);
            }
        }
    }

    private static void reduceWord(long[] buf, int off, int bit, long word, int m, int[] ks)
    {
        int offset = bit - m;
        int j = ks.length;
        while (--j >= 0)
        {
            flipWord(buf, off, offset + ks[j], word);
        }
        flipWord(buf, off, offset, word);
    }

    private static void reduceVectorWise(long[] buf, int off, int len, int words, int m, int[] ks)
    {
        /*
         * NOTE: It's important we go from highest coefficient to lowest, because for the highest
         * one (only) we allow the ranges to partially overlap, and therefore any changes must take
         * effect for the subsequent lower coefficients.
         */
        int baseBit = (words << 6) - m;
        int j = ks.length;
        while (--j >= 0)
        {
            flipVector(buf, off, buf, off + words, len - words, baseBit + ks[j]);
        }
        flipVector(buf, off, buf, off + words, len - words, baseBit);
    }

    private static void flipVector(long[] x, int xOff, long[] y, int yOff, int yLen, int bits)
    {
        xOff += bits >>> 6;
        bits &= 0x3F;

        if (bits == 0)
        {
            add(x, xOff, y, yOff, yLen);
        }
        else
        {
            long carry = addShiftedDown(x, xOff + 1, y, yOff, yLen, 64 - bits);
            x[xOff] ^= carry;
        }
    }

    public LongArray modSquare(int m, int[] ks)
    {
        int len = getUsedLength();
        if (len == 0)
        {
            return this;
        }

        int _2len = len << 1;
        long[] r = new long[_2len];

        int pos = 0;
        while (pos < _2len)
        {
            long mi = m_ints[pos >>> 1];
            r[pos++] = interleave2_32to64((int)mi);
            r[pos++] = interleave2_32to64((int)(mi >>> 32));
        }

        return new LongArray(r, 0, reduceInPlace(r, 0, r.length, m, ks));
    }

    public LongArray modSquareN(int n, int m, int[] ks)
    {
        int len = getUsedLength();
        if (len == 0)
        {
            return this;
        }

        int mLen = (m + 63) >>> 6;
        long[] r = new long[mLen << 1];
        System.arraycopy(m_ints, 0, r, 0, len);

        while (--n >= 0)
        {
            squareInPlace(r, len, m, ks);
            len = reduceInPlace(r, 0, r.length, m, ks);
        }

        return new LongArray(r, 0, len);
    }

    public LongArray square(int m, int[] ks)
    {
        int len = getUsedLength();
        if (len == 0)
        {
            return this;
        }

        int _2len = len << 1;
        long[] r = new long[_2len];

        int pos = 0;
        while (pos < _2len)
        {
            long mi = m_ints[pos >>> 1];
            r[pos++] = interleave2_32to64((int)mi);
            r[pos++] = interleave2_32to64((int)(mi >>> 32));
        }

        return new LongArray(r, 0, r.length);
    }

    private static void squareInPlace(long[] x, int xLen, int m, int[] ks)
    {
        int pos = xLen << 1;
        while (--xLen >= 0)
        {
            long xVal = x[xLen];
            x[--pos] = interleave2_32to64((int)(xVal >>> 32));
            x[--pos] = interleave2_32to64((int)xVal);
        }
    }

    private static void interleave(long[] x, int xOff, long[] z, int zOff, int count, int width)
    {
        switch (width)
        {
        case 3:
            interleave3(x, xOff, z, zOff, count);
            break;
        case 5:
            interleave5(x, xOff, z, zOff, count);
            break;
        case 7:
            interleave7(x, xOff, z, zOff, count);
            break;
        default:
            interleave2_n(x, xOff, z, zOff, count, bitLengths[width] - 1);
            break;
        }
    }

    private static void interleave3(long[] x, int xOff, long[] z, int zOff, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            z[zOff + i] = interleave3(x[xOff + i]);
        }
    }

    private static long interleave3(long x)
    {
        long z = x & (1L << 63);
        return z
            | interleave3_21to63((int)x & 0x1FFFFF)
            | interleave3_21to63((int)(x >>> 21) & 0x1FFFFF) << 1
            | interleave3_21to63((int)(x >>> 42) & 0x1FFFFF) << 2;

//        int zPos = 0, wPos = 0, xPos = 0;
//        for (;;)
//        {
//            z |= ((x >>> xPos) & 1L) << zPos;
//            if (++zPos == 63)
//            {
//                String sz2 = Long.toBinaryString(z);
//                return z;
//            }
//            if ((xPos += 21) >= 63)
//            {
//                xPos = ++wPos;
//            }
//        }
    }

    private static long interleave3_21to63(int x)
    {
        int r00 = INTERLEAVE3_TABLE[x & 0x7F];
        int r21 = INTERLEAVE3_TABLE[(x >>> 7) & 0x7F];
        int r42 = INTERLEAVE3_TABLE[x >>> 14];
        return (r42 & 0xFFFFFFFFL) << 42 | (r21 & 0xFFFFFFFFL) << 21 | (r00 & 0xFFFFFFFFL);
    }

    private static void interleave5(long[] x, int xOff, long[] z, int zOff, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            z[zOff + i] = interleave5(x[xOff + i]);
        }
    }

    private static long interleave5(long x)
    {
        return interleave3_13to65((int)x & 0x1FFF)
            | interleave3_13to65((int)(x >>> 13) & 0x1FFF) << 1
            | interleave3_13to65((int)(x >>> 26) & 0x1FFF) << 2
            | interleave3_13to65((int)(x >>> 39) & 0x1FFF) << 3
            | interleave3_13to65((int)(x >>> 52) & 0x1FFF) << 4;

//        long z = 0;
//        int zPos = 0, wPos = 0, xPos = 0;
//        for (;;)
//        {
//            z |= ((x >>> xPos) & 1L) << zPos;
//            if (++zPos == 64)
//            {
//                return z;
//            }
//            if ((xPos += 13) >= 64)
//            {
//                xPos = ++wPos;
//            }
//        }
    }

    private static long interleave3_13to65(int x)
    {
        int r00 = INTERLEAVE5_TABLE[x & 0x7F];
        int r35 = INTERLEAVE5_TABLE[x >>> 7];
        return (r35 & 0xFFFFFFFFL) << 35 | (r00 & 0xFFFFFFFFL);
    }

    private static void interleave7(long[] x, int xOff, long[] z, int zOff, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            z[zOff + i] = interleave7(x[xOff + i]);
        }
    }

    private static long interleave7(long x)
    {
        long z = x & (1L << 63);
        return z
            | INTERLEAVE7_TABLE[(int)x & 0x1FF]
            | INTERLEAVE7_TABLE[(int)(x >>> 9) & 0x1FF] << 1
            | INTERLEAVE7_TABLE[(int)(x >>> 18) & 0x1FF] << 2
            | INTERLEAVE7_TABLE[(int)(x >>> 27) & 0x1FF] << 3
            | INTERLEAVE7_TABLE[(int)(x >>> 36) & 0x1FF] << 4
            | INTERLEAVE7_TABLE[(int)(x >>> 45) & 0x1FF] << 5
            | INTERLEAVE7_TABLE[(int)(x >>> 54) & 0x1FF] << 6;

//        int zPos = 0, wPos = 0, xPos = 0;
//        for (;;)
//        {
//            z |= ((x >>> xPos) & 1L) << zPos;
//            if (++zPos == 63)
//            {
//                return z;
//            }
//            if ((xPos += 9) >= 63)
//            {
//                xPos = ++wPos;
//            }
//        }
    }

    private static void interleave2_n(long[] x, int xOff, long[] z, int zOff, int count, int rounds)
    {
        for (int i = 0; i < count; ++i)
        {
            z[zOff + i] = interleave2_n(x[xOff + i], rounds);
        }
    }

    private static long interleave2_n(long x, int rounds)
    {
        while (rounds > 1)
        {
            rounds -= 2;
            x = interleave4_16to64((int)x & 0xFFFF)
                | interleave4_16to64((int)(x >>> 16) & 0xFFFF) << 1
                | interleave4_16to64((int)(x >>> 32) & 0xFFFF) << 2
                | interleave4_16to64((int)(x >>> 48) & 0xFFFF) << 3;
        }
        if (rounds > 0)
        {
            x = interleave2_32to64((int)x) | interleave2_32to64((int)(x >>> 32)) << 1;
        }
        return x;
    }

    private static long interleave4_16to64(int x)
    {
        int r00 = INTERLEAVE4_TABLE[x & 0xFF];
        int r32 = INTERLEAVE4_TABLE[x >>> 8];
        return (r32 & 0xFFFFFFFFL) << 32 | (r00 & 0xFFFFFFFFL);
    }

    private static long interleave2_32to64(int x)
    {
        int r00 = INTERLEAVE2_TABLE[x & 0xFF] | INTERLEAVE2_TABLE[(x >>> 8) & 0xFF] << 16;
        int r32 = INTERLEAVE2_TABLE[(x >>> 16) & 0xFF] | INTERLEAVE2_TABLE[x >>> 24] << 16;
        return (r32 & 0xFFFFFFFFL) << 32 | (r00 & 0xFFFFFFFFL);
    }

//    private static LongArray expItohTsujii2(LongArray B, int n, int m, int[] ks)
//    {
//        LongArray t1 = B, t3 = new LongArray(new long[]{ 1L });
//        int scale = 1;
//
//        int numTerms = n;
//        while (numTerms > 1)
//        {
//            if ((numTerms & 1) != 0)
//            {
//                t3 = t3.modMultiply(t1, m, ks);
//                t1 = t1.modSquareN(scale, m, ks);
//            }
//
//            LongArray t2 = t1.modSquareN(scale, m, ks);
//            t1 = t1.modMultiply(t2, m, ks);
//            numTerms >>>= 1; scale <<= 1;
//        }
//
//        return t3.modMultiply(t1, m, ks);
//    }
//
//    private static LongArray expItohTsujii23(LongArray B, int n, int m, int[] ks)
//    {
//        LongArray t1 = B, t3 = new LongArray(new long[]{ 1L });
//        int scale = 1;
//
//        int numTerms = n;
//        while (numTerms > 1)
//        {
//            boolean m03 = numTerms % 3 == 0;
//            boolean m14 = !m03 && (numTerms & 1) != 0;
//
//            if (m14)
//            {
//                t3 = t3.modMultiply(t1, m, ks);
//                t1 = t1.modSquareN(scale, m, ks);
//            }
//
//            LongArray t2 = t1.modSquareN(scale, m, ks);
//            t1 = t1.modMultiply(t2, m, ks);
//
//            if (m03)
//            {
//                t2 = t2.modSquareN(scale, m, ks);
//                t1 = t1.modMultiply(t2, m, ks);
//                numTerms /= 3; scale *= 3;
//            }
//            else
//            {
//                numTerms >>>= 1; scale <<= 1;
//            }
//        }
//
//        return t3.modMultiply(t1, m, ks);
//    }
//
//    private static LongArray expItohTsujii235(LongArray B, int n, int m, int[] ks)
//    {
//        LongArray t1 = B, t4 = new LongArray(new long[]{ 1L });
//        int scale = 1;
//
//        int numTerms = n;
//        while (numTerms > 1)
//        {
//            if (numTerms % 5 == 0)
//            {
////                t1 = expItohTsujii23(t1, 5, m, ks);
//
//                LongArray t3 = t1;
//                t1 = t1.modSquareN(scale, m, ks);
//
//                LongArray t2 = t1.modSquareN(scale, m, ks);
//                t1 = t1.modMultiply(t2, m, ks);
//                t2 = t1.modSquareN(scale << 1, m, ks);
//                t1 = t1.modMultiply(t2, m, ks);
//
//                t1 = t1.modMultiply(t3, m, ks);
//
//                numTerms /= 5; scale *= 5;
//                continue;
//            }
//
//            boolean m03 = numTerms % 3 == 0;
//            boolean m14 = !m03 && (numTerms & 1) != 0;
//
//            if (m14)
//            {
//                t4 = t4.modMultiply(t1, m, ks);
//                t1 = t1.modSquareN(scale, m, ks);
//            }
//
//            LongArray t2 = t1.modSquareN(scale, m, ks);
//            t1 = t1.modMultiply(t2, m, ks);
//
//            if (m03)
//            {
//                t2 = t2.modSquareN(scale, m, ks);
//                t1 = t1.modMultiply(t2, m, ks);
//                numTerms /= 3; scale *= 3;
//            }
//            else
//            {
//                numTerms >>>= 1; scale <<= 1;
//            }
//        }
//
//        return t4.modMultiply(t1, m, ks);
//    }

    public LongArray modInverse(int m, int[] ks)
    {
        /*
         * Fermat's Little Theorem
         */
//        LongArray A = this;
//        LongArray B = A.modSquare(m, ks);
//        LongArray R0 = B, R1 = B;
//        for (int i = 2; i < m; ++i)
//        {
//            R1 = R1.modSquare(m, ks);
//            R0 = R0.modMultiply(R1, m, ks);
//        }
//
//        return R0;

        /*
         * Itoh-Tsujii
         */
//        LongArray B = modSquare(m, ks);
//        switch (m)
//        {
//        case 409:
//            return expItohTsujii23(B, m - 1, m, ks);
//        case 571:
//            return expItohTsujii235(B, m - 1, m, ks);
//        case 163:
//        case 233:
//        case 283:
//        default:
//            return expItohTsujii2(B, m - 1, m, ks);
//        }

        /*
         * Inversion in F2m using the extended Euclidean algorithm
         * 
         * Input: A nonzero polynomial a(z) of degree at most m-1
         * Output: a(z)^(-1) mod f(z)
         */
        int uzDegree = degree();
        if (uzDegree == 0)
        {
            throw new IllegalStateException();
        }
        if (uzDegree == 1)
        {
            return this;
        }

        // u(z) := a(z)
        LongArray uz = (LongArray)clone();

        int t = (m + 63) >>> 6;

        // v(z) := f(z)
        LongArray vz = new LongArray(t);
        reduceBit(vz.m_ints, 0, m, m, ks);

        // g1(z) := 1, g2(z) := 0
        LongArray g1z = new LongArray(t);
        g1z.m_ints[0] = 1L;
        LongArray g2z = new LongArray(t);

        int[] uvDeg = new int[]{ uzDegree, m + 1 };
        LongArray[] uv = new LongArray[]{ uz, vz };

        int[] ggDeg = new int[]{ 1, 0 };
        LongArray[] gg = new LongArray[]{ g1z, g2z };

        int b = 1;
        int duv1 = uvDeg[b];
        int dgg1 = ggDeg[b];
        int j = duv1 - uvDeg[1 - b];

        for (;;)
        {
            if (j < 0)
            {
                j = -j;
                uvDeg[b] = duv1;
                ggDeg[b] = dgg1;
                b = 1 - b;
                duv1 = uvDeg[b];
                dgg1 = ggDeg[b];
            }

            uv[b].addShiftedByBitsSafe(uv[1 - b], uvDeg[1 - b], j);

            int duv2 = uv[b].degreeFrom(duv1);
            if (duv2 == 0)
            {
                return gg[1 - b];
            }

            {
                int dgg2 = ggDeg[1 - b];
                gg[b].addShiftedByBitsSafe(gg[1 - b], dgg2, j);
                dgg2 += j;

                if (dgg2 > dgg1)
                {
                    dgg1 = dgg2;
                }
                else if (dgg2 == dgg1)
                {
                    dgg1 = gg[b].degreeFrom(dgg1);
                }
            }

            j += (duv2 - duv1);
            duv1 = duv2;
        }
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof LongArray))
        {
            return false;
        }
        LongArray other = (LongArray) o;
        int usedLen = getUsedLength();
        if (other.getUsedLength() != usedLen)
        {
            return false;
        }
        for (int i = 0; i < usedLen; i++)
        {
            if (m_ints[i] != other.m_ints[i])
            {
                return false;
            }
        }
        return true;
    }

    public int hashCode()
    {
        int usedLen = getUsedLength();
        int hash = 1;
        for (int i = 0; i < usedLen; i++)
        {
            long mi = m_ints[i];
            hash *= 31;
            hash ^= (int)mi;
            hash *= 31;
            hash ^= (int)(mi >>> 32);
        }
        return hash;
    }

    public Object clone()
    {
        return new LongArray(Arrays.clone(m_ints));
    }

    public String toString()
    {
        int i = getUsedLength();
        if (i == 0)
        {
            return "0";
        }

        StringBuffer sb = new StringBuffer(Long.toBinaryString(m_ints[--i]));
        while (--i >= 0)
        {
            String s = Long.toBinaryString(m_ints[i]);

            // Add leading zeroes, except for highest significant word
            int len = s.length();
            if (len < 64)
            {
                sb.append(ZEROES.substring(len));
            }

            sb.append(s);
        }
        return sb.toString();
    }
}