package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * an implementation of Rijndael, based on the documentation and reference implementation
 * by Paulo Barreto, Vincent Rijmen, for v2.0 August '99.
 * <p>
 * Note: this implementation is based on information prior to final NIST publication.
 */
public class RijndaelEngine
    implements BlockCipher
{
    private static final int MAXROUNDS = 14;

    private static final int MAXKC = (256/4);

    private static final byte[] logtable = {
        (byte)0,    (byte)0,    (byte)25,   (byte)1,    (byte)50,   (byte)2,    (byte)26,   (byte)198,
        (byte)75,   (byte)199,  (byte)27,   (byte)104,  (byte)51,   (byte)238,  (byte)223,  (byte)3,
        (byte)100,  (byte)4,    (byte)224,  (byte)14,   (byte)52,   (byte)141,  (byte)129,  (byte)239,
        (byte)76,   (byte)113,  (byte)8,    (byte)200,  (byte)248,  (byte)105,  (byte)28,   (byte)193,
        (byte)125,  (byte)194,  (byte)29,   (byte)181,  (byte)249,  (byte)185,  (byte)39,   (byte)106,
        (byte)77,   (byte)228,  (byte)166,  (byte)114,  (byte)154,  (byte)201,  (byte)9,    (byte)120,
        (byte)101,  (byte)47,   (byte)138,  (byte)5,    (byte)33,   (byte)15,   (byte)225,  (byte)36,
        (byte)18,   (byte)240,  (byte)130,  (byte)69,   (byte)53,   (byte)147,  (byte)218,  (byte)142,
        (byte)150,  (byte)143,  (byte)219,  (byte)189,  (byte)54,   (byte)208,  (byte)206,  (byte)148,
        (byte)19,   (byte)92,   (byte)210,  (byte)241,  (byte)64,   (byte)70,   (byte)131,  (byte)56,
        (byte)102,  (byte)221,  (byte)253,  (byte)48,   (byte)191,  (byte)6,    (byte)139,  (byte)98,
        (byte)179,  (byte)37,   (byte)226,  (byte)152,  (byte)34,   (byte)136,  (byte)145,  (byte)16,
        (byte)126,  (byte)110,  (byte)72,   (byte)195,  (byte)163,  (byte)182,  (byte)30,   (byte)66,
        (byte)58,   (byte)107,  (byte)40,   (byte)84,   (byte)250,  (byte)133,  (byte)61,   (byte)186,
        (byte)43,   (byte)121,  (byte)10,   (byte)21,   (byte)155,  (byte)159,  (byte)94,   (byte)202,
        (byte)78,   (byte)212,  (byte)172,  (byte)229,  (byte)243,  (byte)115,  (byte)167,  (byte)87,
        (byte)175,  (byte)88,   (byte)168,  (byte)80,   (byte)244,  (byte)234,  (byte)214,  (byte)116,
        (byte)79,   (byte)174,  (byte)233,  (byte)213,  (byte)231,  (byte)230,  (byte)173,  (byte)232,
        (byte)44,   (byte)215,  (byte)117,  (byte)122,  (byte)235,  (byte)22,   (byte)11,   (byte)245,
        (byte)89,   (byte)203,  (byte)95,   (byte)176,  (byte)156,  (byte)169,  (byte)81,   (byte)160,
        (byte)127,  (byte)12,   (byte)246,  (byte)111,  (byte)23,   (byte)196,  (byte)73,   (byte)236,
        (byte)216,  (byte)67,   (byte)31,   (byte)45,   (byte)164,  (byte)118,  (byte)123,  (byte)183,
        (byte)204,  (byte)187,  (byte)62,   (byte)90,   (byte)251,  (byte)96,   (byte)177,  (byte)134,
        (byte)59,   (byte)82,   (byte)161,  (byte)108,  (byte)170,  (byte)85,   (byte)41,   (byte)157,
        (byte)151,  (byte)178,  (byte)135,  (byte)144,  (byte)97,   (byte)190,  (byte)220,  (byte)252,
        (byte)188,  (byte)149,  (byte)207,  (byte)205,  (byte)55,   (byte)63,   (byte)91,   (byte)209,
        (byte)83,   (byte)57,   (byte)132,  (byte)60,   (byte)65,   (byte)162,  (byte)109,  (byte)71,
        (byte)20,   (byte)42,   (byte)158,  (byte)93,   (byte)86,   (byte)242,  (byte)211,  (byte)171,
        (byte)68,   (byte)17,   (byte)146,  (byte)217,  (byte)35,   (byte)32,   (byte)46,   (byte)137,
        (byte)180,  (byte)124,  (byte)184,  (byte)38,   (byte)119,  (byte)153,  (byte)227,  (byte)165,
        (byte)103,  (byte)74,   (byte)237,  (byte)222,  (byte)197,  (byte)49,   (byte)254,  (byte)24,
        (byte)13,   (byte)99,   (byte)140,  (byte)128,  (byte)192,  (byte)247,  (byte)112,  (byte)7
    };

    private static final byte[] aLogtable = {
          (byte)0,   (byte)3,   (byte)5,  (byte)15,  (byte)17,  (byte)51,  (byte)85, (byte)255,  (byte)26,  (byte)46, (byte)114, (byte)150, (byte)161, (byte)248,  (byte)19,  (byte)53,
         (byte)95, (byte)225,  (byte)56,  (byte)72, (byte)216, (byte)115, (byte)149, (byte)164, (byte)247,   (byte)2,   (byte)6,  (byte)10,  (byte)30,  (byte)34, (byte)102, (byte)170,
        (byte)229,  (byte)52,  (byte)92, (byte)228,  (byte)55,  (byte)89, (byte)235,  (byte)38, (byte)106, (byte)190, (byte)217, (byte)112, (byte)144, (byte)171, (byte)230,  (byte)49,
         (byte)83, (byte)245,   (byte)4,  (byte)12,  (byte)20,  (byte)60,  (byte)68, (byte)204,  (byte)79, (byte)209, (byte)104, (byte)184, (byte)211, (byte)110, (byte)178, (byte)205,
         (byte)76, (byte)212, (byte)103, (byte)169, (byte)224,  (byte)59,  (byte)77, (byte)215,  (byte)98, (byte)166, (byte)241,   (byte)8,  (byte)24,  (byte)40, (byte)120, (byte)136,
        (byte)131, (byte)158, (byte)185, (byte)208, (byte)107, (byte)189, (byte)220, (byte)127, (byte)129, (byte)152, (byte)179, (byte)206,  (byte)73, (byte)219, (byte)118, (byte)154,
        (byte)181, (byte)196,  (byte)87, (byte)249,  (byte)16,  (byte)48,  (byte)80, (byte)240,  (byte)11,  (byte)29,  (byte)39, (byte)105, (byte)187, (byte)214,  (byte)97, (byte)163,
        (byte)254,  (byte)25,  (byte)43, (byte)125, (byte)135, (byte)146, (byte)173, (byte)236,  (byte)47, (byte)113, (byte)147, (byte)174, (byte)233,  (byte)32,  (byte)96, (byte)160,
        (byte)251,  (byte)22,  (byte)58,  (byte)78, (byte)210, (byte)109, (byte)183, (byte)194,  (byte)93, (byte)231,  (byte)50,  (byte)86, (byte)250,  (byte)21,  (byte)63,  (byte)65,
        (byte)195,  (byte)94, (byte)226,  (byte)61,  (byte)71, (byte)201,  (byte)64, (byte)192,  (byte)91, (byte)237,  (byte)44, (byte)116, (byte)156, (byte)191, (byte)218, (byte)117,
        (byte)159, (byte)186, (byte)213, (byte)100, (byte)172, (byte)239,  (byte)42, (byte)126, (byte)130, (byte)157, (byte)188, (byte)223, (byte)122, (byte)142, (byte)137, (byte)128,
        (byte)155, (byte)182, (byte)193,  (byte)88, (byte)232,  (byte)35, (byte)101, (byte)175, (byte)234,  (byte)37, (byte)111, (byte)177, (byte)200,  (byte)67, (byte)197,  (byte)84,
        (byte)252,  (byte)31,  (byte)33,  (byte)99, (byte)165, (byte)244,   (byte)7,   (byte)9,  (byte)27,  (byte)45, (byte)119, (byte)153, (byte)176, (byte)203,  (byte)70, (byte)202,
         (byte)69, (byte)207,  (byte)74, (byte)222, (byte)121, (byte)139, (byte)134, (byte)145, (byte)168, (byte)227,  (byte)62,  (byte)66, (byte)198,  (byte)81, (byte)243,  (byte)14,
         (byte)18,  (byte)54,  (byte)90, (byte)238,  (byte)41, (byte)123, (byte)141, (byte)140, (byte)143, (byte)138, (byte)133, (byte)148, (byte)167, (byte)242,  (byte)13,  (byte)23,
         (byte)57,  (byte)75, (byte)221, (byte)124, (byte)132, (byte)151, (byte)162, (byte)253,  (byte)28,  (byte)36, (byte)108, (byte)180, (byte)199,  (byte)82, (byte)246,   (byte)1,
          (byte)3,   (byte)5,  (byte)15,  (byte)17,  (byte)51,  (byte)85, (byte)255,  (byte)26,  (byte)46, (byte)114, (byte)150, (byte)161, (byte)248,  (byte)19,  (byte)53,
         (byte)95, (byte)225,  (byte)56,  (byte)72, (byte)216, (byte)115, (byte)149, (byte)164, (byte)247,   (byte)2,   (byte)6,  (byte)10,  (byte)30,  (byte)34, (byte)102, (byte)170,
        (byte)229,  (byte)52,  (byte)92, (byte)228,  (byte)55,  (byte)89, (byte)235,  (byte)38, (byte)106, (byte)190, (byte)217, (byte)112, (byte)144, (byte)171, (byte)230,  (byte)49,
         (byte)83, (byte)245,   (byte)4,  (byte)12,  (byte)20,  (byte)60,  (byte)68, (byte)204,  (byte)79, (byte)209, (byte)104, (byte)184, (byte)211, (byte)110, (byte)178, (byte)205,
         (byte)76, (byte)212, (byte)103, (byte)169, (byte)224,  (byte)59,  (byte)77, (byte)215,  (byte)98, (byte)166, (byte)241,   (byte)8,  (byte)24,  (byte)40, (byte)120, (byte)136,
        (byte)131, (byte)158, (byte)185, (byte)208, (byte)107, (byte)189, (byte)220, (byte)127, (byte)129, (byte)152, (byte)179, (byte)206,  (byte)73, (byte)219, (byte)118, (byte)154,
        (byte)181, (byte)196,  (byte)87, (byte)249,  (byte)16,  (byte)48,  (byte)80, (byte)240,  (byte)11,  (byte)29,  (byte)39, (byte)105, (byte)187, (byte)214,  (byte)97, (byte)163,
        (byte)254,  (byte)25,  (byte)43, (byte)125, (byte)135, (byte)146, (byte)173, (byte)236,  (byte)47, (byte)113, (byte)147, (byte)174, (byte)233,  (byte)32,  (byte)96, (byte)160,
        (byte)251,  (byte)22,  (byte)58,  (byte)78, (byte)210, (byte)109, (byte)183, (byte)194,  (byte)93, (byte)231,  (byte)50,  (byte)86, (byte)250,  (byte)21,  (byte)63,  (byte)65,
        (byte)195,  (byte)94, (byte)226,  (byte)61,  (byte)71, (byte)201,  (byte)64, (byte)192,  (byte)91, (byte)237,  (byte)44, (byte)116, (byte)156, (byte)191, (byte)218, (byte)117,
        (byte)159, (byte)186, (byte)213, (byte)100, (byte)172, (byte)239,  (byte)42, (byte)126, (byte)130, (byte)157, (byte)188, (byte)223, (byte)122, (byte)142, (byte)137, (byte)128,
        (byte)155, (byte)182, (byte)193,  (byte)88, (byte)232,  (byte)35, (byte)101, (byte)175, (byte)234,  (byte)37, (byte)111, (byte)177, (byte)200,  (byte)67, (byte)197,  (byte)84,
        (byte)252,  (byte)31,  (byte)33,  (byte)99, (byte)165, (byte)244,   (byte)7,   (byte)9,  (byte)27,  (byte)45, (byte)119, (byte)153, (byte)176, (byte)203,  (byte)70, (byte)202,
         (byte)69, (byte)207,  (byte)74, (byte)222, (byte)121, (byte)139, (byte)134, (byte)145, (byte)168, (byte)227,  (byte)62,  (byte)66, (byte)198,  (byte)81, (byte)243,  (byte)14,
         (byte)18,  (byte)54,  (byte)90, (byte)238,  (byte)41, (byte)123, (byte)141, (byte)140, (byte)143, (byte)138, (byte)133, (byte)148, (byte)167, (byte)242,  (byte)13,  (byte)23,
         (byte)57,  (byte)75, (byte)221, (byte)124, (byte)132, (byte)151, (byte)162, (byte)253,  (byte)28,  (byte)36, (byte)108, (byte)180, (byte)199,  (byte)82, (byte)246,   (byte)1,
        };

    private static final byte[] S = {
         (byte)99, (byte)124, (byte)119, (byte)123, (byte)242, (byte)107, (byte)111, (byte)197,  (byte)48,   (byte)1, (byte)103,  (byte)43, (byte)254, (byte)215, (byte)171, (byte)118,
        (byte)202, (byte)130, (byte)201, (byte)125, (byte)250,  (byte)89,  (byte)71, (byte)240, (byte)173, (byte)212, (byte)162, (byte)175, (byte)156, (byte)164, (byte)114, (byte)192,
        (byte)183, (byte)253, (byte)147,  (byte)38,  (byte)54,  (byte)63, (byte)247, (byte)204,  (byte)52, (byte)165, (byte)229, (byte)241, (byte)113, (byte)216,  (byte)49,  (byte)21,
          (byte)4, (byte)199,  (byte)35, (byte)195,  (byte)24, (byte)150,   (byte)5, (byte)154,   (byte)7,  (byte)18, (byte)128, (byte)226, (byte)235,  (byte)39, (byte)178, (byte)117,
          (byte)9, (byte)131,  (byte)44,  (byte)26,  (byte)27, (byte)110,  (byte)90, (byte)160,  (byte)82,  (byte)59, (byte)214, (byte)179,  (byte)41, (byte)227,  (byte)47, (byte)132,
         (byte)83, (byte)209,   (byte)0, (byte)237,  (byte)32, (byte)252, (byte)177,  (byte)91, (byte)106, (byte)203, (byte)190,  (byte)57,  (byte)74,  (byte)76,  (byte)88, (byte)207,
        (byte)208, (byte)239, (byte)170, (byte)251,  (byte)67,  (byte)77,  (byte)51, (byte)133,  (byte)69, (byte)249,   (byte)2, (byte)127,  (byte)80,  (byte)60, (byte)159, (byte)168,
         (byte)81, (byte)163,  (byte)64, (byte)143, (byte)146, (byte)157,  (byte)56, (byte)245, (byte)188, (byte)182, (byte)218,  (byte)33,  (byte)16, (byte)255, (byte)243, (byte)210,
        (byte)205,  (byte)12,  (byte)19, (byte)236,  (byte)95, (byte)151,  (byte)68,  (byte)23, (byte)196, (byte)167, (byte)126,  (byte)61, (byte)100,  (byte)93,  (byte)25, (byte)115,
         (byte)96, (byte)129,  (byte)79, (byte)220,  (byte)34,  (byte)42, (byte)144, (byte)136,  (byte)70, (byte)238, (byte)184,  (byte)20, (byte)222,  (byte)94,  (byte)11, (byte)219,
        (byte)224,  (byte)50,  (byte)58,  (byte)10,  (byte)73,   (byte)6,  (byte)36,  (byte)92, (byte)194, (byte)211, (byte)172,  (byte)98, (byte)145, (byte)149, (byte)228, (byte)121,
        (byte)231, (byte)200,  (byte)55, (byte)109, (byte)141, (byte)213,  (byte)78, (byte)169, (byte)108,  (byte)86, (byte)244, (byte)234, (byte)101, (byte)122, (byte)174,   (byte)8,
        (byte)186, (byte)120,  (byte)37,  (byte)46,  (byte)28, (byte)166, (byte)180, (byte)198, (byte)232, (byte)221, (byte)116,  (byte)31,  (byte)75, (byte)189, (byte)139, (byte)138,
        (byte)112,  (byte)62, (byte)181, (byte)102,  (byte)72,   (byte)3, (byte)246,  (byte)14,  (byte)97,  (byte)53,  (byte)87, (byte)185, (byte)134, (byte)193,  (byte)29, (byte)158,
        (byte)225, (byte)248, (byte)152,  (byte)17, (byte)105, (byte)217, (byte)142, (byte)148, (byte)155,  (byte)30, (byte)135, (byte)233, (byte)206,  (byte)85,  (byte)40, (byte)223,
        (byte)140, (byte)161, (byte)137,  (byte)13, (byte)191, (byte)230,  (byte)66, (byte)104,  (byte)65, (byte)153,  (byte)45,  (byte)15, (byte)176,  (byte)84, (byte)187,  (byte)22,
    };

    private static final byte[] Si = {
         (byte)82,   (byte)9, (byte)106, (byte)213,  (byte)48,  (byte)54, (byte)165,  (byte)56, (byte)191,  (byte)64, (byte)163, (byte)158, (byte)129, (byte)243, (byte)215, (byte)251,
        (byte)124, (byte)227,  (byte)57, (byte)130, (byte)155,  (byte)47, (byte)255, (byte)135,  (byte)52, (byte)142,  (byte)67,  (byte)68, (byte)196, (byte)222, (byte)233, (byte)203,
         (byte)84, (byte)123, (byte)148,  (byte)50, (byte)166, (byte)194,  (byte)35,  (byte)61, (byte)238,  (byte)76, (byte)149,  (byte)11,  (byte)66, (byte)250, (byte)195,  (byte)78,
          (byte)8,  (byte)46, (byte)161, (byte)102,  (byte)40, (byte)217,  (byte)36, (byte)178, (byte)118,  (byte)91, (byte)162,  (byte)73, (byte)109, (byte)139, (byte)209,  (byte)37,
        (byte)114, (byte)248, (byte)246, (byte)100, (byte)134, (byte)104, (byte)152,  (byte)22, (byte)212, (byte)164,  (byte)92, (byte)204,  (byte)93, (byte)101, (byte)182, (byte)146,
        (byte)108, (byte)112,  (byte)72,  (byte)80, (byte)253, (byte)237, (byte)185, (byte)218,  (byte)94,  (byte)21,  (byte)70,  (byte)87, (byte)167, (byte)141, (byte)157, (byte)132,
        (byte)144, (byte)216, (byte)171,   (byte)0, (byte)140, (byte)188, (byte)211,  (byte)10, (byte)247, (byte)228,  (byte)88,   (byte)5, (byte)184, (byte)179,  (byte)69,   (byte)6,
        (byte)208,  (byte)44,  (byte)30, (byte)143, (byte)202,  (byte)63,  (byte)15,   (byte)2, (byte)193, (byte)175, (byte)189,   (byte)3,   (byte)1,  (byte)19, (byte)138, (byte)107,
         (byte)58, (byte)145,  (byte)17,  (byte)65,  (byte)79, (byte)103, (byte)220, (byte)234, (byte)151, (byte)242, (byte)207, (byte)206, (byte)240, (byte)180, (byte)230, (byte)115,
        (byte)150, (byte)172, (byte)116,  (byte)34, (byte)231, (byte)173,  (byte)53, (byte)133, (byte)226, (byte)249,  (byte)55, (byte)232,  (byte)28, (byte)117, (byte)223, (byte)110,
         (byte)71, (byte)241,  (byte)26, (byte)113,  (byte)29,  (byte)41, (byte)197, (byte)137, (byte)111, (byte)183,  (byte)98,  (byte)14, (byte)170,  (byte)24, (byte)190,  (byte)27,
        (byte)252,  (byte)86,  (byte)62,  (byte)75, (byte)198, (byte)210, (byte)121,  (byte)32, (byte)154, (byte)219, (byte)192, (byte)254, (byte)120, (byte)205,  (byte)90, (byte)244,
         (byte)31, (byte)221, (byte)168,  (byte)51, (byte)136,   (byte)7, (byte)199,  (byte)49, (byte)177,  (byte)18,  (byte)16,  (byte)89,  (byte)39, (byte)128, (byte)236,  (byte)95,
         (byte)96,  (byte)81, (byte)127, (byte)169,  (byte)25, (byte)181,  (byte)74,  (byte)13,  (byte)45, (byte)229, (byte)122, (byte)159, (byte)147, (byte)201, (byte)156, (byte)239,
        (byte)160, (byte)224,  (byte)59,  (byte)77, (byte)174,  (byte)42, (byte)245, (byte)176, (byte)200, (byte)235, (byte)187,  (byte)60, (byte)131,  (byte)83, (byte)153,  (byte)97,
         (byte)23,  (byte)43,   (byte)4, (byte)126, (byte)186, (byte)119, (byte)214,  (byte)38, (byte)225, (byte)105,  (byte)20,  (byte)99,  (byte)85,  (byte)33,  (byte)12, (byte)125,
        };

    private static final int[] rcon = {
          0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91 };

    static byte[][] shifts0 =
    {
       { 0, 8, 16, 24 },
       { 0, 8, 16, 24 },
       { 0, 8, 16, 24 },
       { 0, 8, 16, 32 },
       { 0, 8, 24, 32 }
    };

    static byte[][] shifts1 =
    {
       { 0, 24, 16, 8 },
       { 0, 32, 24, 16 },
       { 0, 40, 32, 24 },
       { 0, 48, 40, 24 },
       { 0, 56, 40, 32 }
    };

    /**
     * multiply two elements of GF(2^m)
     * needed for MixColumn and InvMixColumn
     */
    private byte mul0x2(
        int b)
    {
        if (b != 0)
        {
            return aLogtable[25 + (logtable[b] & 0xff)];
        }
        else
        {
            return 0;
        }
    }

    private byte mul0x3(
        int b)
    {
        if (b != 0)
        {
            return aLogtable[1 + (logtable[b] & 0xff)];
        }
        else
        {
            return 0;
        }
    }

    private byte mul0x9(
        int b)
    {
        if (b >= 0)
        {
            return aLogtable[199 + b];
        }
        else
        {
            return 0;
        }
    }

    private byte mul0xb(
        int b)
    {
        if (b >= 0)
        {
            return aLogtable[104 + b];
        }
        else
        {
            return 0;
        }
    }

    private byte mul0xd(
        int b)
    {
        if (b >= 0)
        {
            return aLogtable[238 + b];
        }
        else
        {
            return 0;
        }
    }

    private byte mul0xe(
        int b)
    {
        if (b >= 0)
        {
            return aLogtable[223 + b];
        }
        else
        {
            return 0;
        }
    }

    /**
     * xor corresponding text input and round key input bytes
     */
    private void KeyAddition(
        long[] rk)
    {
        A0 ^= rk[0];
        A1 ^= rk[1];
        A2 ^= rk[2];
        A3 ^= rk[3];
    }

    private long shift(
        long    r,
        int     shift)
    {
        return (((r >>> shift) | (r << (BC - shift)))) & BC_MASK;
    }

    /**
     * Row 0 remains unchanged
     * The other three rows are shifted a variable amount
     */
    private void ShiftRow(
        byte[]      shiftsSC)
    {
        A1 = shift(A1, shiftsSC[1]);
        A2 = shift(A2, shiftsSC[2]);
        A3 = shift(A3, shiftsSC[3]);
    }

    private long applyS(
        long    r,
        byte[]  box)
    {
        long    res = 0;

        for (int j = 0; j < BC; j += 8)
        {
            res |= (long)(box[(int)((r >> j) & 0xff)] & 0xff) << j;
        }

        return res;
    }

    /**
     * Replace every byte of the input by the byte at that place
     * in the nonlinear S-box
     */
    private void Substitution(
        byte[]      box)
    {
        A0 = applyS(A0, box);
        A1 = applyS(A1, box);
        A2 = applyS(A2, box);
        A3 = applyS(A3, box);
    }

    /**
     * Mix the bytes of every column in a linear way
     */
    private void MixColumn()
    {
        long r0, r1, r2, r3;

        r0 = r1 = r2 = r3 = 0;

        for (int j = 0; j < BC; j += 8)
        {
            int a0 = (int)((A0 >> j) & 0xff);
            int a1 = (int)((A1 >> j) & 0xff);
            int a2 = (int)((A2 >> j) & 0xff);
            int a3 = (int)((A3 >> j) & 0xff);

            r0 |= (long)((mul0x2(a0) ^ mul0x3(a1) ^ a2 ^ a3) & 0xff) << j;

            r1 |= (long)((mul0x2(a1) ^ mul0x3(a2) ^ a3 ^ a0) & 0xff) << j;

            r2 |= (long)((mul0x2(a2) ^ mul0x3(a3) ^ a0 ^ a1) & 0xff) << j;

            r3 |= (long)((mul0x2(a3) ^ mul0x3(a0) ^ a1 ^ a2) & 0xff) << j;
        }

        A0 = r0;
        A1 = r1;
        A2 = r2;
        A3 = r3;
    }

    /**
     * Mix the bytes of every column in a linear way
     * This is the opposite operation of Mixcolumn
     */
    private void InvMixColumn()
    {
        long r0, r1, r2, r3;

        r0 = r1 = r2 = r3 = 0;
        for (int j = 0; j < BC; j += 8)
        {
            int a0 = (int)((A0 >> j) & 0xff);
            int a1 = (int)((A1 >> j) & 0xff);
            int a2 = (int)((A2 >> j) & 0xff);
            int a3 = (int)((A3 >> j) & 0xff);

            //
            // pre-lookup the log table
            //
            a0 = (a0 != 0) ? (logtable[a0 & 0xff] & 0xff) : -1;
            a1 = (a1 != 0) ? (logtable[a1 & 0xff] & 0xff) : -1;
            a2 = (a2 != 0) ? (logtable[a2 & 0xff] & 0xff) : -1;
            a3 = (a3 != 0) ? (logtable[a3 & 0xff] & 0xff) : -1;

            r0 |= (long)((mul0xe(a0) ^ mul0xb(a1) ^ mul0xd(a2) ^ mul0x9(a3)) & 0xff) << j;

            r1 |= (long)((mul0xe(a1) ^ mul0xb(a2) ^ mul0xd(a3) ^ mul0x9(a0)) & 0xff) << j;

            r2 |= (long)((mul0xe(a2) ^ mul0xb(a3) ^ mul0xd(a0) ^ mul0x9(a1)) & 0xff) << j;

            r3 |= (long)((mul0xe(a3) ^ mul0xb(a0) ^ mul0xd(a1) ^ mul0x9(a2)) & 0xff) << j;
        }

        A0 = r0;
        A1 = r1;
        A2 = r2;
        A3 = r3;
    }

    /**
     * Calculate the necessary round keys
     * The number of calculations depends on keyBits and blockBits
     */
    private long[][] generateWorkingKey(
        byte[]      key)
    {
        int         KC;
        int         t, rconpointer = 0;
        int         keyBits = key.length * 8;
        byte[][]    tk = new byte[4][MAXKC];
        long[][]    W = new long[MAXROUNDS+1][4];

        switch (keyBits)
        {
        case 128:
            KC = 4;
            break;
        case 160:
            KC = 5;
            break;
        case 192:
            KC = 6;
            break;
        case 224:
            KC = 7;
            break;
        case 256:
            KC = 8;
            break;
        default :
            throw new IllegalArgumentException("Key length not 128/160/192/224/256 bits.");
        }

        if (keyBits >= blockBits)
        {
            ROUNDS = KC + 6;
        }
        else
        {
            ROUNDS = (BC / 8) + 6;
        }

        //
        // copy the key into the processing area
        //
        int index = 0;

        for (int i = 0; i < key.length; i++)
        {
            tk[i % 4][i / 4] = key[index++];
        }

        t = 0;

        //
        // copy values into round key array
        //
        for (int j = 0; (j < KC) && (t < (ROUNDS+1)*(BC / 8)); j++, t++)
        {
            for (int i = 0; i < 4; i++)
            {
                W[t / (BC / 8)][i] |= (long)(tk[i][j] & 0xff) << ((t * 8) % BC);
            }
        }

        //
        // while not enough round key material calculated
        // calculate new values
        //
        while (t < (ROUNDS+1)*(BC/8))
        {
            for (int i = 0; i < 4; i++)
            {
                tk[i][0] ^= S[tk[(i+1)%4][KC-1] & 0xff];
            }
            tk[0][0] ^= rcon[rconpointer++];

            if (KC <= 6)
            {
                for (int j = 1; j < KC; j++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        tk[i][j] ^= tk[i][j-1];
                    }
                }
            }
            else
            {
                for (int j = 1; j < 4; j++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        tk[i][j] ^= tk[i][j-1];
                    }
                }
                for (int i = 0; i < 4; i++)
                {
                    tk[i][4] ^= S[tk[i][3] & 0xff];
                }
                for (int j = 5; j < KC; j++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        tk[i][j] ^= tk[i][j-1];
                    }
                }
            }

            //
            // copy values into round key array
            //
            for (int j = 0; (j < KC) && (t < (ROUNDS+1)*(BC/8)); j++, t++)
            {
                for (int i = 0; i < 4; i++)
                {
                    W[t / (BC/8)][i] |= (long)(tk[i][j] & 0xff) << ((t * 8) % (BC));
                }
            }
        }

        return W;
    }

    private int         BC;
    private long        BC_MASK;
    private int         ROUNDS;
    private int         blockBits;
    private long[][]    workingKey;
    private long        A0, A1, A2, A3;
    private boolean     forEncryption;
    private byte[]      shifts0SC;
    private byte[]      shifts1SC;

    /**
     * default constructor - 128 bit block size.
     */
    public RijndaelEngine()
    {
        this(128);
    }

    /**
     * basic constructor - set the cipher up for a given blocksize
     *
     * @param blockBits the blocksize in bits, must be 128, 192, or 256.
     */
    public RijndaelEngine(
        int blockBits)
    {
        switch (blockBits)
        {
        case 128:
            BC = 32;
            BC_MASK = 0xffffffffL;
            shifts0SC = shifts0[0];
            shifts1SC = shifts1[0];
            break;
        case 160:
            BC = 40;
            BC_MASK = 0xffffffffffL;
            shifts0SC = shifts0[1];
            shifts1SC = shifts1[1];
            break;
        case 192:
            BC = 48;
            BC_MASK = 0xffffffffffffL;
            shifts0SC = shifts0[2];
            shifts1SC = shifts1[2];
            break;
        case 224:
            BC = 56;
            BC_MASK = 0xffffffffffffffL;
            shifts0SC = shifts0[3];
            shifts1SC = shifts1[3];
            break;
        case 256:
            BC = 64;
            BC_MASK = 0xffffffffffffffffL;
            shifts0SC = shifts0[4];
            shifts1SC = shifts1[4];
            break;
        default:
            throw new IllegalArgumentException("unknown blocksize to Rijndael");
        }

        this.blockBits = blockBits;
    }

    /**
     * initialise a Rijndael cipher.
     *
     * @param forEncryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    public void init(
        boolean           forEncryption,
        CipherParameters  params)
    {
        if (params instanceof KeyParameter)
        {
            workingKey = generateWorkingKey(((KeyParameter)params).getKey());
            this.forEncryption = forEncryption;
            return;
        }

        throw new IllegalArgumentException("invalid parameter passed to Rijndael init - " + params.getClass().getName());
    }

    public String getAlgorithmName()
    {
        return "Rijndael";
    }

    public int getBlockSize()
    {
        return BC / 2;
    }

    public int processBlock(
        byte[] in,
        int inOff,
        byte[] out,
        int outOff)
    {
        if (workingKey == null)
        {
            throw new IllegalStateException("Rijndael engine not initialised");
        }

        if ((inOff + (BC / 2)) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + (BC / 2)) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        if (forEncryption)
        {
            unpackBlock(in, inOff);
            encryptBlock(workingKey);
            packBlock(out, outOff);
        }
        else
        {
            unpackBlock(in, inOff);
            decryptBlock(workingKey);
            packBlock(out, outOff);
        }

        return BC / 2;
    }

    public void reset()
    {
    }

    private void unpackBlock(
        byte[]      bytes,
        int         off)
    {
        int     index = off;

        A0 = (bytes[index++] & 0xff);
        A1 = (bytes[index++] & 0xff);
        A2 = (bytes[index++] & 0xff);
        A3 = (bytes[index++] & 0xff);

        for (int j = 8; j != BC; j += 8)
        {
            A0 |= (long)(bytes[index++] & 0xff) << j;
            A1 |= (long)(bytes[index++] & 0xff) << j;
            A2 |= (long)(bytes[index++] & 0xff) << j;
            A3 |= (long)(bytes[index++] & 0xff) << j;
        }
    }

    private void packBlock(
        byte[]      bytes,
        int         off)
    {
        int     index = off;

        for (int j = 0; j != BC; j += 8)
        {
            bytes[index++] = (byte)(A0 >> j);
            bytes[index++] = (byte)(A1 >> j);
            bytes[index++] = (byte)(A2 >> j);
            bytes[index++] = (byte)(A3 >> j);
        }
    }

    private void encryptBlock(
        long[][] rk)
    {
        int r;

        //
        // begin with a key addition
        //
        KeyAddition(rk[0]);

        //
        // ROUNDS-1 ordinary rounds
        //
        for (r = 1; r < ROUNDS; r++)
        {
            Substitution(S);
            ShiftRow(shifts0SC);
            MixColumn();
            KeyAddition(rk[r]);
        }

        //
        // Last round is special: there is no MixColumn
        //
        Substitution(S);
        ShiftRow(shifts0SC);
        KeyAddition(rk[ROUNDS]);
    }

    private void decryptBlock(
        long[][] rk)
    {
        int r;

        // To decrypt: apply the inverse operations of the encrypt routine,
        //             in opposite order
        //
        // (KeyAddition is an involution: it 's equal to its inverse)
        // (the inverse of Substitution with table S is Substitution with the inverse table of S)
        // (the inverse of Shiftrow is Shiftrow over a suitable distance)
        //

        // First the special round:
        //   without InvMixColumn
        //   with extra KeyAddition
        //
        KeyAddition(rk[ROUNDS]);
        Substitution(Si);
        ShiftRow(shifts1SC);

        //
        // ROUNDS-1 ordinary rounds
        //
        for (r = ROUNDS-1; r > 0; r--)
        {
            KeyAddition(rk[r]);
            InvMixColumn();
            Substitution(Si);
            ShiftRow(shifts1SC);
        }

        //
        // End with the extra key addition
        //
        KeyAddition(rk[0]);
    }
}
