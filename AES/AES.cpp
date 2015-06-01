#include "stdafx.h"
#include "AES.h"
#include "KeySchedule.h"
#include "Rijndael.h"
#include <iostream>
#include <fstream>
#include <memory>
#include <vector>
using namespace std;

// // https://github.com/kokke/tiny-AES128-C/blob/master/aes.c

// http://www.codeproject.com/Articles/1380/A-C-Implementation-of-the-Rijndael-Encryption-Decr
// http://en.wikipedia.org/wiki/Rijndael_key_schedule
// http://en.wikipedia.org/wiki/Rijndael_S-box
// http://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael.27s_finite_field

#define SR(i, j) srTmp[i] = sboxTmp[j];

#define MC(i, j0, j1, j2, j3) {						            \
	mcTmp[i] = (uint8_t)(galois2[sboxTmp[j0]] ^ galois3[sboxTmp[j1]] ^ sboxTmp[j2] ^ sboxTmp[j3]);	    \
	mcTmp[i+1] = (uint8_t)(sboxTmp[j0] ^ galois2[sboxTmp[j1]] ^ galois3[sboxTmp[j2]] ^ sboxTmp[j3]);	\
	mcTmp[i+2] = (uint8_t)(sboxTmp[j0] ^ sboxTmp[j1] ^ galois2[sboxTmp[j2]] ^ galois3[sboxTmp[j3]]);	\
	mcTmp[i+3] = (uint8_t)(galois3[sboxTmp[j0]] ^ sboxTmp[j1] ^ sboxTmp[j2] ^ galois2[sboxTmp[j3]]);	\
}

#define MC_inv(i,j0,j1,j2,j3) {																										\
	mc_InvTmp[i] = (uint8_t)(galois14[sboxTemp[j0]] ^ galois11[sboxTemp[j1]] ^ galois13[sboxTemp[j2]] ^ galois9[sboxTemp[j3]]);		\
	mc_InvTmp[i+1] = (uint8_t)(galois9[sboxTemp[j0]] ^ galois14[sboxTemp[j1]] ^ galois11[sboxTemp[j2]] ^ galois13[sboxTemp[j3]]);	\
	mc_InvTmp[i+2] = (uint8_t)(galois13[sboxTemp[j0]] ^ galois9[sboxTemp[j1]] ^ galois14[sboxTemp[j2]] ^ galois11[sboxTemp[j3]]);	\
	mc_InvTmp[i+3] = (uint8_t)(galois11[sboxTemp[j0]] ^ galois13[sboxTemp[j1]] ^ galois9[sboxTemp[j2]] ^ galois14[sboxTemp[j3]]);	\
}

static vector<uint8_t> FileReadAllBytes(char const* filename)
{
	ifstream ifs(filename, ios::binary | ios::ate);

	ifstream::pos_type pos = ifs.tellg();

	vector<uint8_t> result(pos);

	ifs.seekg(0, ios::beg);
	ifs.read((char*)&result[0], pos);

	return result;
}

static vector<uint8_t> Encrypt(vector<uint8_t> key, vector<uint8_t> data)
{
	KeySchedule keySchedule(key);

	auto newKey = keySchedule.GetNextKey();

	// sbox
	auto sboxTmp = vector<uint8_t>(16);
	for (auto i = 0; i < 16; i++)
	{
		sboxTmp[i] = sbox[data[i]];
	}

	sboxTmp[0] = 0xDB;
	sboxTmp[5] = 0x13;
	sboxTmp[10] = 0x53;
	sboxTmp[15] = 0x45;

	// shift rows / mix column
	auto mcTmp = vector<uint8_t>(16);
	MC(0, 0, 5, 10, 15)
	MC(4, 4, 9, 14, 3)
	MC(8, 8, 13, 2, 7)
	MC(12, 12, 1, 6, 11)
	
	// db 13 53 45
	// 8e 4d a1 bc
	return mcTmp;
}

static vector<uint8_t> decrypt(vector<uint8_t> key, vector<uint8_t> message) {
	KeySchedule keySchedule(key);

	auto sboxTemp = vector<uint8_t>(16);
	for (auto i = 0; i < 16; i++)
	{
		sboxTemp[i] = sbox[message[i]];
	}


	//InverseMixColumns
	auto mc_InvTmp = vector<uint8_t>(16);
	MC_inv(0,0,4,8,12);
	MC_inv(4,13,1,5,9);
	MC_inv(8,10,14,2,6);
	MC_inv(12,7,11,15,3)

	return mc_InvTmp;

}



int _tmain(int argc, _TCHAR* argv[])
{
	auto key = FileReadAllBytes("..\\key.txt");
	auto data = FileReadAllBytes("..\\text.txt");

	auto res = Encrypt(key, data);

	return 0;
}
