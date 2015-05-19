// $Id: SHAviteSmallCore.java 222 2010-06-09 10:47:13Z tp $

package fr.cryptohash;

/**
 * This class implements SHAvite-224 and SHAvite-256.
 *
 * <pre>
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 * </pre>
 *
 * @version   $Revision: 222 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

abstract class SHAviteSmallCore extends DigestEngine {

	private int[] h, rk;

	/**
	 * Create the object.
	 */
	SHAviteSmallCore()
	{
	}

	private static final int[] AES0 = {
		0xA56363C6, 0x847C7CF8, 0x997777EE, 0x8D7B7BF6,
		0x0DF2F2FF, 0xBD6B6BD6, 0xB16F6FDE, 0x54C5C591,
		0x50303060, 0x03010102, 0xA96767CE, 0x7D2B2B56,
		0x19FEFEE7, 0x62D7D7B5, 0xE6ABAB4D, 0x9A7676EC,
		0x45CACA8F, 0x9D82821F, 0x40C9C989, 0x877D7DFA,
		0x15FAFAEF, 0xEB5959B2, 0xC947478E, 0x0BF0F0FB,
		0xECADAD41, 0x67D4D4B3, 0xFDA2A25F, 0xEAAFAF45,
		0xBF9C9C23, 0xF7A4A453, 0x967272E4, 0x5BC0C09B,
		0xC2B7B775, 0x1CFDFDE1, 0xAE93933D, 0x6A26264C,
		0x5A36366C, 0x413F3F7E, 0x02F7F7F5, 0x4FCCCC83,
		0x5C343468, 0xF4A5A551, 0x34E5E5D1, 0x08F1F1F9,
		0x937171E2, 0x73D8D8AB, 0x53313162, 0x3F15152A,
		0x0C040408, 0x52C7C795, 0x65232346, 0x5EC3C39D,
		0x28181830, 0xA1969637, 0x0F05050A, 0xB59A9A2F,
		0x0907070E, 0x36121224, 0x9B80801B, 0x3DE2E2DF,
		0x26EBEBCD, 0x6927274E, 0xCDB2B27F, 0x9F7575EA,
		0x1B090912, 0x9E83831D, 0x742C2C58, 0x2E1A1A34,
		0x2D1B1B36, 0xB26E6EDC, 0xEE5A5AB4, 0xFBA0A05B,
		0xF65252A4, 0x4D3B3B76, 0x61D6D6B7, 0xCEB3B37D,
		0x7B292952, 0x3EE3E3DD, 0x712F2F5E, 0x97848413,
		0xF55353A6, 0x68D1D1B9, 0x00000000, 0x2CEDEDC1,
		0x60202040, 0x1FFCFCE3, 0xC8B1B179, 0xED5B5BB6,
		0xBE6A6AD4, 0x46CBCB8D, 0xD9BEBE67, 0x4B393972,
		0xDE4A4A94, 0xD44C4C98, 0xE85858B0, 0x4ACFCF85,
		0x6BD0D0BB, 0x2AEFEFC5, 0xE5AAAA4F, 0x16FBFBED,
		0xC5434386, 0xD74D4D9A, 0x55333366, 0x94858511,
		0xCF45458A, 0x10F9F9E9, 0x06020204, 0x817F7FFE,
		0xF05050A0, 0x443C3C78, 0xBA9F9F25, 0xE3A8A84B,
		0xF35151A2, 0xFEA3A35D, 0xC0404080, 0x8A8F8F05,
		0xAD92923F, 0xBC9D9D21, 0x48383870, 0x04F5F5F1,
		0xDFBCBC63, 0xC1B6B677, 0x75DADAAF, 0x63212142,
		0x30101020, 0x1AFFFFE5, 0x0EF3F3FD, 0x6DD2D2BF,
		0x4CCDCD81, 0x140C0C18, 0x35131326, 0x2FECECC3,
		0xE15F5FBE, 0xA2979735, 0xCC444488, 0x3917172E,
		0x57C4C493, 0xF2A7A755, 0x827E7EFC, 0x473D3D7A,
		0xAC6464C8, 0xE75D5DBA, 0x2B191932, 0x957373E6,
		0xA06060C0, 0x98818119, 0xD14F4F9E, 0x7FDCDCA3,
		0x66222244, 0x7E2A2A54, 0xAB90903B, 0x8388880B,
		0xCA46468C, 0x29EEEEC7, 0xD3B8B86B, 0x3C141428,
		0x79DEDEA7, 0xE25E5EBC, 0x1D0B0B16, 0x76DBDBAD,
		0x3BE0E0DB, 0x56323264, 0x4E3A3A74, 0x1E0A0A14,
		0xDB494992, 0x0A06060C, 0x6C242448, 0xE45C5CB8,
		0x5DC2C29F, 0x6ED3D3BD, 0xEFACAC43, 0xA66262C4,
		0xA8919139, 0xA4959531, 0x37E4E4D3, 0x8B7979F2,
		0x32E7E7D5, 0x43C8C88B, 0x5937376E, 0xB76D6DDA,
		0x8C8D8D01, 0x64D5D5B1, 0xD24E4E9C, 0xE0A9A949,
		0xB46C6CD8, 0xFA5656AC, 0x07F4F4F3, 0x25EAEACF,
		0xAF6565CA, 0x8E7A7AF4, 0xE9AEAE47, 0x18080810,
		0xD5BABA6F, 0x887878F0, 0x6F25254A, 0x722E2E5C,
		0x241C1C38, 0xF1A6A657, 0xC7B4B473, 0x51C6C697,
		0x23E8E8CB, 0x7CDDDDA1, 0x9C7474E8, 0x211F1F3E,
		0xDD4B4B96, 0xDCBDBD61, 0x868B8B0D, 0x858A8A0F,
		0x907070E0, 0x423E3E7C, 0xC4B5B571, 0xAA6666CC,
		0xD8484890, 0x05030306, 0x01F6F6F7, 0x120E0E1C,
		0xA36161C2, 0x5F35356A, 0xF95757AE, 0xD0B9B969,
		0x91868617, 0x58C1C199, 0x271D1D3A, 0xB99E9E27,
		0x38E1E1D9, 0x13F8F8EB, 0xB398982B, 0x33111122,
		0xBB6969D2, 0x70D9D9A9, 0x898E8E07, 0xA7949433,
		0xB69B9B2D, 0x221E1E3C, 0x92878715, 0x20E9E9C9,
		0x49CECE87, 0xFF5555AA, 0x78282850, 0x7ADFDFA5,
		0x8F8C8C03, 0xF8A1A159, 0x80898909, 0x170D0D1A,
		0xDABFBF65, 0x31E6E6D7, 0xC6424284, 0xB86868D0,
		0xC3414182, 0xB0999929, 0x772D2D5A, 0x110F0F1E,
		0xCBB0B07B, 0xFC5454A8, 0xD6BBBB6D, 0x3A16162C
	};

	private static final int[] AES1 = {
		0x6363C6A5, 0x7C7CF884, 0x7777EE99, 0x7B7BF68D,
		0xF2F2FF0D, 0x6B6BD6BD, 0x6F6FDEB1, 0xC5C59154,
		0x30306050, 0x01010203, 0x6767CEA9, 0x2B2B567D,
		0xFEFEE719, 0xD7D7B562, 0xABAB4DE6, 0x7676EC9A,
		0xCACA8F45, 0x82821F9D, 0xC9C98940, 0x7D7DFA87,
		0xFAFAEF15, 0x5959B2EB, 0x47478EC9, 0xF0F0FB0B,
		0xADAD41EC, 0xD4D4B367, 0xA2A25FFD, 0xAFAF45EA,
		0x9C9C23BF, 0xA4A453F7, 0x7272E496, 0xC0C09B5B,
		0xB7B775C2, 0xFDFDE11C, 0x93933DAE, 0x26264C6A,
		0x36366C5A, 0x3F3F7E41, 0xF7F7F502, 0xCCCC834F,
		0x3434685C, 0xA5A551F4, 0xE5E5D134, 0xF1F1F908,
		0x7171E293, 0xD8D8AB73, 0x31316253, 0x15152A3F,
		0x0404080C, 0xC7C79552, 0x23234665, 0xC3C39D5E,
		0x18183028, 0x969637A1, 0x05050A0F, 0x9A9A2FB5,
		0x07070E09, 0x12122436, 0x80801B9B, 0xE2E2DF3D,
		0xEBEBCD26, 0x27274E69, 0xB2B27FCD, 0x7575EA9F,
		0x0909121B, 0x83831D9E, 0x2C2C5874, 0x1A1A342E,
		0x1B1B362D, 0x6E6EDCB2, 0x5A5AB4EE, 0xA0A05BFB,
		0x5252A4F6, 0x3B3B764D, 0xD6D6B761, 0xB3B37DCE,
		0x2929527B, 0xE3E3DD3E, 0x2F2F5E71, 0x84841397,
		0x5353A6F5, 0xD1D1B968, 0x00000000, 0xEDEDC12C,
		0x20204060, 0xFCFCE31F, 0xB1B179C8, 0x5B5BB6ED,
		0x6A6AD4BE, 0xCBCB8D46, 0xBEBE67D9, 0x3939724B,
		0x4A4A94DE, 0x4C4C98D4, 0x5858B0E8, 0xCFCF854A,
		0xD0D0BB6B, 0xEFEFC52A, 0xAAAA4FE5, 0xFBFBED16,
		0x434386C5, 0x4D4D9AD7, 0x33336655, 0x85851194,
		0x45458ACF, 0xF9F9E910, 0x02020406, 0x7F7FFE81,
		0x5050A0F0, 0x3C3C7844, 0x9F9F25BA, 0xA8A84BE3,
		0x5151A2F3, 0xA3A35DFE, 0x404080C0, 0x8F8F058A,
		0x92923FAD, 0x9D9D21BC, 0x38387048, 0xF5F5F104,
		0xBCBC63DF, 0xB6B677C1, 0xDADAAF75, 0x21214263,
		0x10102030, 0xFFFFE51A, 0xF3F3FD0E, 0xD2D2BF6D,
		0xCDCD814C, 0x0C0C1814, 0x13132635, 0xECECC32F,
		0x5F5FBEE1, 0x979735A2, 0x444488CC, 0x17172E39,
		0xC4C49357, 0xA7A755F2, 0x7E7EFC82, 0x3D3D7A47,
		0x6464C8AC, 0x5D5DBAE7, 0x1919322B, 0x7373E695,
		0x6060C0A0, 0x81811998, 0x4F4F9ED1, 0xDCDCA37F,
		0x22224466, 0x2A2A547E, 0x90903BAB, 0x88880B83,
		0x46468CCA, 0xEEEEC729, 0xB8B86BD3, 0x1414283C,
		0xDEDEA779, 0x5E5EBCE2, 0x0B0B161D, 0xDBDBAD76,
		0xE0E0DB3B, 0x32326456, 0x3A3A744E, 0x0A0A141E,
		0x494992DB, 0x06060C0A, 0x2424486C, 0x5C5CB8E4,
		0xC2C29F5D, 0xD3D3BD6E, 0xACAC43EF, 0x6262C4A6,
		0x919139A8, 0x959531A4, 0xE4E4D337, 0x7979F28B,
		0xE7E7D532, 0xC8C88B43, 0x37376E59, 0x6D6DDAB7,
		0x8D8D018C, 0xD5D5B164, 0x4E4E9CD2, 0xA9A949E0,
		0x6C6CD8B4, 0x5656ACFA, 0xF4F4F307, 0xEAEACF25,
		0x6565CAAF, 0x7A7AF48E, 0xAEAE47E9, 0x08081018,
		0xBABA6FD5, 0x7878F088, 0x25254A6F, 0x2E2E5C72,
		0x1C1C3824, 0xA6A657F1, 0xB4B473C7, 0xC6C69751,
		0xE8E8CB23, 0xDDDDA17C, 0x7474E89C, 0x1F1F3E21,
		0x4B4B96DD, 0xBDBD61DC, 0x8B8B0D86, 0x8A8A0F85,
		0x7070E090, 0x3E3E7C42, 0xB5B571C4, 0x6666CCAA,
		0x484890D8, 0x03030605, 0xF6F6F701, 0x0E0E1C12,
		0x6161C2A3, 0x35356A5F, 0x5757AEF9, 0xB9B969D0,
		0x86861791, 0xC1C19958, 0x1D1D3A27, 0x9E9E27B9,
		0xE1E1D938, 0xF8F8EB13, 0x98982BB3, 0x11112233,
		0x6969D2BB, 0xD9D9A970, 0x8E8E0789, 0x949433A7,
		0x9B9B2DB6, 0x1E1E3C22, 0x87871592, 0xE9E9C920,
		0xCECE8749, 0x5555AAFF, 0x28285078, 0xDFDFA57A,
		0x8C8C038F, 0xA1A159F8, 0x89890980, 0x0D0D1A17,
		0xBFBF65DA, 0xE6E6D731, 0x424284C6, 0x6868D0B8,
		0x414182C3, 0x999929B0, 0x2D2D5A77, 0x0F0F1E11,
		0xB0B07BCB, 0x5454A8FC, 0xBBBB6DD6, 0x16162C3A
	};

	private static final int[] AES2 = {
		0x63C6A563, 0x7CF8847C, 0x77EE9977, 0x7BF68D7B,
		0xF2FF0DF2, 0x6BD6BD6B, 0x6FDEB16F, 0xC59154C5,
		0x30605030, 0x01020301, 0x67CEA967, 0x2B567D2B,
		0xFEE719FE, 0xD7B562D7, 0xAB4DE6AB, 0x76EC9A76,
		0xCA8F45CA, 0x821F9D82, 0xC98940C9, 0x7DFA877D,
		0xFAEF15FA, 0x59B2EB59, 0x478EC947, 0xF0FB0BF0,
		0xAD41ECAD, 0xD4B367D4, 0xA25FFDA2, 0xAF45EAAF,
		0x9C23BF9C, 0xA453F7A4, 0x72E49672, 0xC09B5BC0,
		0xB775C2B7, 0xFDE11CFD, 0x933DAE93, 0x264C6A26,
		0x366C5A36, 0x3F7E413F, 0xF7F502F7, 0xCC834FCC,
		0x34685C34, 0xA551F4A5, 0xE5D134E5, 0xF1F908F1,
		0x71E29371, 0xD8AB73D8, 0x31625331, 0x152A3F15,
		0x04080C04, 0xC79552C7, 0x23466523, 0xC39D5EC3,
		0x18302818, 0x9637A196, 0x050A0F05, 0x9A2FB59A,
		0x070E0907, 0x12243612, 0x801B9B80, 0xE2DF3DE2,
		0xEBCD26EB, 0x274E6927, 0xB27FCDB2, 0x75EA9F75,
		0x09121B09, 0x831D9E83, 0x2C58742C, 0x1A342E1A,
		0x1B362D1B, 0x6EDCB26E, 0x5AB4EE5A, 0xA05BFBA0,
		0x52A4F652, 0x3B764D3B, 0xD6B761D6, 0xB37DCEB3,
		0x29527B29, 0xE3DD3EE3, 0x2F5E712F, 0x84139784,
		0x53A6F553, 0xD1B968D1, 0x00000000, 0xEDC12CED,
		0x20406020, 0xFCE31FFC, 0xB179C8B1, 0x5BB6ED5B,
		0x6AD4BE6A, 0xCB8D46CB, 0xBE67D9BE, 0x39724B39,
		0x4A94DE4A, 0x4C98D44C, 0x58B0E858, 0xCF854ACF,
		0xD0BB6BD0, 0xEFC52AEF, 0xAA4FE5AA, 0xFBED16FB,
		0x4386C543, 0x4D9AD74D, 0x33665533, 0x85119485,
		0x458ACF45, 0xF9E910F9, 0x02040602, 0x7FFE817F,
		0x50A0F050, 0x3C78443C, 0x9F25BA9F, 0xA84BE3A8,
		0x51A2F351, 0xA35DFEA3, 0x4080C040, 0x8F058A8F,
		0x923FAD92, 0x9D21BC9D, 0x38704838, 0xF5F104F5,
		0xBC63DFBC, 0xB677C1B6, 0xDAAF75DA, 0x21426321,
		0x10203010, 0xFFE51AFF, 0xF3FD0EF3, 0xD2BF6DD2,
		0xCD814CCD, 0x0C18140C, 0x13263513, 0xECC32FEC,
		0x5FBEE15F, 0x9735A297, 0x4488CC44, 0x172E3917,
		0xC49357C4, 0xA755F2A7, 0x7EFC827E, 0x3D7A473D,
		0x64C8AC64, 0x5DBAE75D, 0x19322B19, 0x73E69573,
		0x60C0A060, 0x81199881, 0x4F9ED14F, 0xDCA37FDC,
		0x22446622, 0x2A547E2A, 0x903BAB90, 0x880B8388,
		0x468CCA46, 0xEEC729EE, 0xB86BD3B8, 0x14283C14,
		0xDEA779DE, 0x5EBCE25E, 0x0B161D0B, 0xDBAD76DB,
		0xE0DB3BE0, 0x32645632, 0x3A744E3A, 0x0A141E0A,
		0x4992DB49, 0x060C0A06, 0x24486C24, 0x5CB8E45C,
		0xC29F5DC2, 0xD3BD6ED3, 0xAC43EFAC, 0x62C4A662,
		0x9139A891, 0x9531A495, 0xE4D337E4, 0x79F28B79,
		0xE7D532E7, 0xC88B43C8, 0x376E5937, 0x6DDAB76D,
		0x8D018C8D, 0xD5B164D5, 0x4E9CD24E, 0xA949E0A9,
		0x6CD8B46C, 0x56ACFA56, 0xF4F307F4, 0xEACF25EA,
		0x65CAAF65, 0x7AF48E7A, 0xAE47E9AE, 0x08101808,
		0xBA6FD5BA, 0x78F08878, 0x254A6F25, 0x2E5C722E,
		0x1C38241C, 0xA657F1A6, 0xB473C7B4, 0xC69751C6,
		0xE8CB23E8, 0xDDA17CDD, 0x74E89C74, 0x1F3E211F,
		0x4B96DD4B, 0xBD61DCBD, 0x8B0D868B, 0x8A0F858A,
		0x70E09070, 0x3E7C423E, 0xB571C4B5, 0x66CCAA66,
		0x4890D848, 0x03060503, 0xF6F701F6, 0x0E1C120E,
		0x61C2A361, 0x356A5F35, 0x57AEF957, 0xB969D0B9,
		0x86179186, 0xC19958C1, 0x1D3A271D, 0x9E27B99E,
		0xE1D938E1, 0xF8EB13F8, 0x982BB398, 0x11223311,
		0x69D2BB69, 0xD9A970D9, 0x8E07898E, 0x9433A794,
		0x9B2DB69B, 0x1E3C221E, 0x87159287, 0xE9C920E9,
		0xCE8749CE, 0x55AAFF55, 0x28507828, 0xDFA57ADF,
		0x8C038F8C, 0xA159F8A1, 0x89098089, 0x0D1A170D,
		0xBF65DABF, 0xE6D731E6, 0x4284C642, 0x68D0B868,
		0x4182C341, 0x9929B099, 0x2D5A772D, 0x0F1E110F,
		0xB07BCBB0, 0x54A8FC54, 0xBB6DD6BB, 0x162C3A16
	};

	private static final int[] AES3 = {
		0xC6A56363, 0xF8847C7C, 0xEE997777, 0xF68D7B7B,
		0xFF0DF2F2, 0xD6BD6B6B, 0xDEB16F6F, 0x9154C5C5,
		0x60503030, 0x02030101, 0xCEA96767, 0x567D2B2B,
		0xE719FEFE, 0xB562D7D7, 0x4DE6ABAB, 0xEC9A7676,
		0x8F45CACA, 0x1F9D8282, 0x8940C9C9, 0xFA877D7D,
		0xEF15FAFA, 0xB2EB5959, 0x8EC94747, 0xFB0BF0F0,
		0x41ECADAD, 0xB367D4D4, 0x5FFDA2A2, 0x45EAAFAF,
		0x23BF9C9C, 0x53F7A4A4, 0xE4967272, 0x9B5BC0C0,
		0x75C2B7B7, 0xE11CFDFD, 0x3DAE9393, 0x4C6A2626,
		0x6C5A3636, 0x7E413F3F, 0xF502F7F7, 0x834FCCCC,
		0x685C3434, 0x51F4A5A5, 0xD134E5E5, 0xF908F1F1,
		0xE2937171, 0xAB73D8D8, 0x62533131, 0x2A3F1515,
		0x080C0404, 0x9552C7C7, 0x46652323, 0x9D5EC3C3,
		0x30281818, 0x37A19696, 0x0A0F0505, 0x2FB59A9A,
		0x0E090707, 0x24361212, 0x1B9B8080, 0xDF3DE2E2,
		0xCD26EBEB, 0x4E692727, 0x7FCDB2B2, 0xEA9F7575,
		0x121B0909, 0x1D9E8383, 0x58742C2C, 0x342E1A1A,
		0x362D1B1B, 0xDCB26E6E, 0xB4EE5A5A, 0x5BFBA0A0,
		0xA4F65252, 0x764D3B3B, 0xB761D6D6, 0x7DCEB3B3,
		0x527B2929, 0xDD3EE3E3, 0x5E712F2F, 0x13978484,
		0xA6F55353, 0xB968D1D1, 0x00000000, 0xC12CEDED,
		0x40602020, 0xE31FFCFC, 0x79C8B1B1, 0xB6ED5B5B,
		0xD4BE6A6A, 0x8D46CBCB, 0x67D9BEBE, 0x724B3939,
		0x94DE4A4A, 0x98D44C4C, 0xB0E85858, 0x854ACFCF,
		0xBB6BD0D0, 0xC52AEFEF, 0x4FE5AAAA, 0xED16FBFB,
		0x86C54343, 0x9AD74D4D, 0x66553333, 0x11948585,
		0x8ACF4545, 0xE910F9F9, 0x04060202, 0xFE817F7F,
		0xA0F05050, 0x78443C3C, 0x25BA9F9F, 0x4BE3A8A8,
		0xA2F35151, 0x5DFEA3A3, 0x80C04040, 0x058A8F8F,
		0x3FAD9292, 0x21BC9D9D, 0x70483838, 0xF104F5F5,
		0x63DFBCBC, 0x77C1B6B6, 0xAF75DADA, 0x42632121,
		0x20301010, 0xE51AFFFF, 0xFD0EF3F3, 0xBF6DD2D2,
		0x814CCDCD, 0x18140C0C, 0x26351313, 0xC32FECEC,
		0xBEE15F5F, 0x35A29797, 0x88CC4444, 0x2E391717,
		0x9357C4C4, 0x55F2A7A7, 0xFC827E7E, 0x7A473D3D,
		0xC8AC6464, 0xBAE75D5D, 0x322B1919, 0xE6957373,
		0xC0A06060, 0x19988181, 0x9ED14F4F, 0xA37FDCDC,
		0x44662222, 0x547E2A2A, 0x3BAB9090, 0x0B838888,
		0x8CCA4646, 0xC729EEEE, 0x6BD3B8B8, 0x283C1414,
		0xA779DEDE, 0xBCE25E5E, 0x161D0B0B, 0xAD76DBDB,
		0xDB3BE0E0, 0x64563232, 0x744E3A3A, 0x141E0A0A,
		0x92DB4949, 0x0C0A0606, 0x486C2424, 0xB8E45C5C,
		0x9F5DC2C2, 0xBD6ED3D3, 0x43EFACAC, 0xC4A66262,
		0x39A89191, 0x31A49595, 0xD337E4E4, 0xF28B7979,
		0xD532E7E7, 0x8B43C8C8, 0x6E593737, 0xDAB76D6D,
		0x018C8D8D, 0xB164D5D5, 0x9CD24E4E, 0x49E0A9A9,
		0xD8B46C6C, 0xACFA5656, 0xF307F4F4, 0xCF25EAEA,
		0xCAAF6565, 0xF48E7A7A, 0x47E9AEAE, 0x10180808,
		0x6FD5BABA, 0xF0887878, 0x4A6F2525, 0x5C722E2E,
		0x38241C1C, 0x57F1A6A6, 0x73C7B4B4, 0x9751C6C6,
		0xCB23E8E8, 0xA17CDDDD, 0xE89C7474, 0x3E211F1F,
		0x96DD4B4B, 0x61DCBDBD, 0x0D868B8B, 0x0F858A8A,
		0xE0907070, 0x7C423E3E, 0x71C4B5B5, 0xCCAA6666,
		0x90D84848, 0x06050303, 0xF701F6F6, 0x1C120E0E,
		0xC2A36161, 0x6A5F3535, 0xAEF95757, 0x69D0B9B9,
		0x17918686, 0x9958C1C1, 0x3A271D1D, 0x27B99E9E,
		0xD938E1E1, 0xEB13F8F8, 0x2BB39898, 0x22331111,
		0xD2BB6969, 0xA970D9D9, 0x07898E8E, 0x33A79494,
		0x2DB69B9B, 0x3C221E1E, 0x15928787, 0xC920E9E9,
		0x8749CECE, 0xAAFF5555, 0x50782828, 0xA57ADFDF,
		0x038F8C8C, 0x59F8A1A1, 0x09808989, 0x1A170D0D,
		0x65DABFBF, 0xD731E6E6, 0x84C64242, 0xD0B86868,
		0x82C34141, 0x29B09999, 0x5A772D2D, 0x1E110F0F,
		0x7BCBB0B0, 0xA8FC5454, 0x6DD6BBBB, 0x2C3A1616
	};

	/** @see Digest */
	public int getBlockLength()
	{
		return 64;
	}

	/** @see DigestEngine */
	protected Digest copyState(SHAviteSmallCore dst)
	{
		System.arraycopy(h, 0, dst.h, 0, h.length);
		return super.copyState(dst);
	}

	/** @see DigestEngine */
	protected void engineReset()
	{
		System.arraycopy(getInitVal(), 0, h, 0, h.length);
	}

	/**
	 * Get the initial value for this algorithm.
	 *
	 * @return  the initial value
	 */
	abstract int[] getInitVal();

	/** @see DigestEngine */
	protected void doPadding(byte[] output, int outputOffset)
	{
		int ptr = flush();
		long bc = getBlockCount();
		long bitLen = (bc << 9) + (ptr << 3);
		int cnt0 = (int)bitLen;
		int cnt1 = (int)(bitLen >>> 32);
		byte[] buf = getBlockBuffer();
		if (ptr == 0) {
			buf[0] = (byte)0x80;
			for (int i = 1; i < 54; i ++)
				buf[i] = 0;
			cnt0 = cnt1 = 0;
		} else if (ptr < 54) {
			buf[ptr ++] = (byte)0x80;
			while (ptr < 54)
				buf[ptr ++] = 0;
		} else {
			buf[ptr ++] = (byte)0x80;
			while (ptr < 64)
				buf[ptr ++] = 0;
			process(buf, cnt0, cnt1);
			for (int i = 0; i < 54; i ++)
				buf[i] = 0;
			cnt0 = cnt1 = 0;
		}
		encodeLEInt((int)bitLen, buf, 54);
		encodeLEInt((int)(bitLen >>> 32), buf, 58);
		int dlen = getDigestLength();
		buf[62] = (byte)(dlen << 3);
		buf[63] = (byte)(dlen >>> 5);
		process(buf, cnt0, cnt1);
		for (int i = 0; i < dlen; i += 4)
			encodeLEInt(h[i >>> 2], output, outputOffset + i);
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		h = new int[8];
		rk = new int[144];
		engineReset();
	}

	/**
	 * Encode the 32-bit word {@code val} into the array
	 * {@code buf} at offset {@code off}, in little-endian
	 * convention (least significant byte first).
	 *
	 * @param val   the value to encode
	 * @param buf   the destination buffer
	 * @param off   the destination offset
	 */
	private static final void encodeLEInt(int val, byte[] buf, int off)
	{
		buf[off + 0] = (byte)val;
		buf[off + 1] = (byte)(val >>> 8);
		buf[off + 2] = (byte)(val >>> 16);
		buf[off + 3] = (byte)(val >>> 24);
	}

	/**
	 * Decode a 32-bit little-endian word from the array {@code buf}
	 * at offset {@code off}.
	 *
	 * @param buf   the source buffer
	 * @param off   the source offset
	 * @return  the decoded value
	 */
	private static final int decodeLEInt(byte[] buf, int off)
	{
		return (buf[off] & 0xFF)
			| ((buf[off + 1] & 0xFF) << 8)
			| ((buf[off + 2] & 0xFF) << 16)
			| ((buf[off + 3] & 0xFF) << 24);
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		long bitLen = (getBlockCount() + 1) << 9;
		process(data, (int)bitLen, (int)(bitLen >>> 32));
	}

	private void process(byte[] data, int cnt0, int cnt1)
	{
		int p0, p1, p2, p3, p4, p5, p6, p7;
		int u;

		for (u = 0; u < 16; u += 4) {
			rk[u + 0] = decodeLEInt(data, (u << 2) +  0);
			rk[u + 1] = decodeLEInt(data, (u << 2) +  4);
			rk[u + 2] = decodeLEInt(data, (u << 2) +  8);
			rk[u + 3] = decodeLEInt(data, (u << 2) + 12);
		}
		for (int r = 0; r < 4; r ++) {
			for (int s = 0; s < 2; s ++) {
				int x0, x1, x2, x3;
				int t0, t1, t2, t3;

				x0 = rk[u - 15];
				x1 = rk[u - 14];
				x2 = rk[u - 13];
				x3 = rk[u - 16];
				t0 = AES0[x0 & 0xFF]
					^ AES1[(x1 >>> 8) & 0xFF]
					^ AES2[(x2 >>> 16) & 0xFF]
					^ AES3[x3 >>> 24];
				t1 = AES0[x1 & 0xFF]
					^ AES1[(x2 >>> 8) & 0xFF]
					^ AES2[(x3 >>> 16) & 0xFF]
					^ AES3[x0 >>> 24];
				t2 = AES0[x2 & 0xFF]
					^ AES1[(x3 >>> 8) & 0xFF]
					^ AES2[(x0 >>> 16) & 0xFF]
					^ AES3[x1 >>> 24];
				t3 = AES0[x3 & 0xFF]
					^ AES1[(x0 >>> 8) & 0xFF]
					^ AES2[(x1 >>> 16) & 0xFF]
					^ AES3[x2 >>> 24];
				rk[u + 0] = t0 ^ rk[u - 4];
				rk[u + 1] = t1 ^ rk[u - 3];
				rk[u + 2] = t2 ^ rk[u - 2];
				rk[u + 3] = t3 ^ rk[u - 1];
				if (u == 16) {
					rk[ 16] ^= cnt0;
					rk[ 17] ^= ~cnt1;
				} else if (u == 56) {
					rk[ 57] ^= cnt1;
					rk[ 58] ^= ~cnt0;
				}
				u += 4;

				x0 = rk[u - 15];
				x1 = rk[u - 14];
				x2 = rk[u - 13];
				x3 = rk[u - 16];
				t0 = AES0[x0 & 0xFF]
					^ AES1[(x1 >>> 8) & 0xFF]
					^ AES2[(x2 >>> 16) & 0xFF]
					^ AES3[x3 >>> 24];
				t1 = AES0[x1 & 0xFF]
					^ AES1[(x2 >>> 8) & 0xFF]
					^ AES2[(x3 >>> 16) & 0xFF]
					^ AES3[x0 >>> 24];
				t2 = AES0[x2 & 0xFF]
					^ AES1[(x3 >>> 8) & 0xFF]
					^ AES2[(x0 >>> 16) & 0xFF]
					^ AES3[x1 >>> 24];
				t3 = AES0[x3 & 0xFF]
					^ AES1[(x0 >>> 8) & 0xFF]
					^ AES2[(x1 >>> 16) & 0xFF]
					^ AES3[x2 >>> 24];
				rk[u + 0] = t0 ^ rk[u - 4];
				rk[u + 1] = t1 ^ rk[u - 3];
				rk[u + 2] = t2 ^ rk[u - 2];
				rk[u + 3] = t3 ^ rk[u - 1];
				if (u == 84) {
					rk[ 86] ^= cnt1;
					rk[ 87] ^= ~cnt0;
				} else if (u == 124) {
					rk[124] ^= cnt0;
					rk[127] ^= ~cnt1;
				}
				u += 4;
			}
			for (int s = 0; s < 4; s ++) {
				rk[u + 0] = rk[u - 16] ^ rk[u - 3];
				rk[u + 1] = rk[u - 15] ^ rk[u - 2];
				rk[u + 2] = rk[u - 14] ^ rk[u - 1];
				rk[u + 3] = rk[u - 13] ^ rk[u - 0];
				u += 4;
			}
		}

		p0 = h[0x0];
		p1 = h[0x1];
		p2 = h[0x2];
		p3 = h[0x3];
		p4 = h[0x4];
		p5 = h[0x5];
		p6 = h[0x6];
		p7 = h[0x7];
		u = 0;
		for (int r = 0; r < 6; r ++) {
			int x0, x1, x2, x3;
			int t0, t1, t2, t3;

			x0 = p4 ^ rk[u ++];
			x1 = p5 ^ rk[u ++];
			x2 = p6 ^ rk[u ++];
			x3 = p7 ^ rk[u ++];
			t0 = AES0[x0 & 0xFF]
				^ AES1[(x1 >>> 8) & 0xFF]
				^ AES2[(x2 >>> 16) & 0xFF]
				^ AES3[x3 >>> 24];
			t1 = AES0[x1 & 0xFF]
				^ AES1[(x2 >>> 8) & 0xFF]
				^ AES2[(x3 >>> 16) & 0xFF]
				^ AES3[x0 >>> 24];
			t2 = AES0[x2 & 0xFF]
				^ AES1[(x3 >>> 8) & 0xFF]
				^ AES2[(x0 >>> 16) & 0xFF]
				^ AES3[x1 >>> 24];
			t3 = AES0[x3 & 0xFF]
				^ AES1[(x0 >>> 8) & 0xFF]
				^ AES2[(x1 >>> 16) & 0xFF]
				^ AES3[x2 >>> 24];
			x0 = t0 ^ rk[u ++];
			x1 = t1 ^ rk[u ++];
			x2 = t2 ^ rk[u ++];
			x3 = t3 ^ rk[u ++];
			t0 = AES0[x0 & 0xFF]
				^ AES1[(x1 >>> 8) & 0xFF]
				^ AES2[(x2 >>> 16) & 0xFF]
				^ AES3[x3 >>> 24];
			t1 = AES0[x1 & 0xFF]
				^ AES1[(x2 >>> 8) & 0xFF]
				^ AES2[(x3 >>> 16) & 0xFF]
				^ AES3[x0 >>> 24];
			t2 = AES0[x2 & 0xFF]
				^ AES1[(x3 >>> 8) & 0xFF]
				^ AES2[(x0 >>> 16) & 0xFF]
				^ AES3[x1 >>> 24];
			t3 = AES0[x3 & 0xFF]
				^ AES1[(x0 >>> 8) & 0xFF]
				^ AES2[(x1 >>> 16) & 0xFF]
				^ AES3[x2 >>> 24];
			x0 = t0 ^ rk[u ++];
			x1 = t1 ^ rk[u ++];
			x2 = t2 ^ rk[u ++];
			x3 = t3 ^ rk[u ++];
			t0 = AES0[x0 & 0xFF]
				^ AES1[(x1 >>> 8) & 0xFF]
				^ AES2[(x2 >>> 16) & 0xFF]
				^ AES3[x3 >>> 24];
			t1 = AES0[x1 & 0xFF]
				^ AES1[(x2 >>> 8) & 0xFF]
				^ AES2[(x3 >>> 16) & 0xFF]
				^ AES3[x0 >>> 24];
			t2 = AES0[x2 & 0xFF]
				^ AES1[(x3 >>> 8) & 0xFF]
				^ AES2[(x0 >>> 16) & 0xFF]
				^ AES3[x1 >>> 24];
			t3 = AES0[x3 & 0xFF]
				^ AES1[(x0 >>> 8) & 0xFF]
				^ AES2[(x1 >>> 16) & 0xFF]
				^ AES3[x2 >>> 24];
			p0 ^= t0;
			p1 ^= t1;
			p2 ^= t2;
			p3 ^= t3;

			x0 = p0 ^ rk[u ++];
			x1 = p1 ^ rk[u ++];
			x2 = p2 ^ rk[u ++];
			x3 = p3 ^ rk[u ++];
			t0 = AES0[x0 & 0xFF]
				^ AES1[(x1 >>> 8) & 0xFF]
				^ AES2[(x2 >>> 16) & 0xFF]
				^ AES3[x3 >>> 24];
			t1 = AES0[x1 & 0xFF]
				^ AES1[(x2 >>> 8) & 0xFF]
				^ AES2[(x3 >>> 16) & 0xFF]
				^ AES3[x0 >>> 24];
			t2 = AES0[x2 & 0xFF]
				^ AES1[(x3 >>> 8) & 0xFF]
				^ AES2[(x0 >>> 16) & 0xFF]
				^ AES3[x1 >>> 24];
			t3 = AES0[x3 & 0xFF]
				^ AES1[(x0 >>> 8) & 0xFF]
				^ AES2[(x1 >>> 16) & 0xFF]
				^ AES3[x2 >>> 24];
			x0 = t0 ^ rk[u ++];
			x1 = t1 ^ rk[u ++];
			x2 = t2 ^ rk[u ++];
			x3 = t3 ^ rk[u ++];
			t0 = AES0[x0 & 0xFF]
				^ AES1[(x1 >>> 8) & 0xFF]
				^ AES2[(x2 >>> 16) & 0xFF]
				^ AES3[x3 >>> 24];
			t1 = AES0[x1 & 0xFF]
				^ AES1[(x2 >>> 8) & 0xFF]
				^ AES2[(x3 >>> 16) & 0xFF]
				^ AES3[x0 >>> 24];
			t2 = AES0[x2 & 0xFF]
				^ AES1[(x3 >>> 8) & 0xFF]
				^ AES2[(x0 >>> 16) & 0xFF]
				^ AES3[x1 >>> 24];
			t3 = AES0[x3 & 0xFF]
				^ AES1[(x0 >>> 8) & 0xFF]
				^ AES2[(x1 >>> 16) & 0xFF]
				^ AES3[x2 >>> 24];
			x0 = t0 ^ rk[u ++];
			x1 = t1 ^ rk[u ++];
			x2 = t2 ^ rk[u ++];
			x3 = t3 ^ rk[u ++];
			t0 = AES0[x0 & 0xFF]
				^ AES1[(x1 >>> 8) & 0xFF]
				^ AES2[(x2 >>> 16) & 0xFF]
				^ AES3[x3 >>> 24];
			t1 = AES0[x1 & 0xFF]
				^ AES1[(x2 >>> 8) & 0xFF]
				^ AES2[(x3 >>> 16) & 0xFF]
				^ AES3[x0 >>> 24];
			t2 = AES0[x2 & 0xFF]
				^ AES1[(x3 >>> 8) & 0xFF]
				^ AES2[(x0 >>> 16) & 0xFF]
				^ AES3[x1 >>> 24];
			t3 = AES0[x3 & 0xFF]
				^ AES1[(x0 >>> 8) & 0xFF]
				^ AES2[(x1 >>> 16) & 0xFF]
				^ AES3[x2 >>> 24];
			p4 ^= t0;
			p5 ^= t1;
			p6 ^= t2;
			p7 ^= t3;
		}
		h[0x0] ^= p0;
		h[0x1] ^= p1;
		h[0x2] ^= p2;
		h[0x3] ^= p3;
		h[0x4] ^= p4;
		h[0x5] ^= p5;
		h[0x6] ^= p6;
		h[0x7] ^= p7;
	}

	/** @see Digest */
	public String toString()
	{
		return "SHAvite-" + (getDigestLength() << 3);
	}
}
