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

int _tmain(int argc, _TCHAR* argv[])
{
	auto key = FileReadAllBytes("..\\key.txt");
	auto data = FileReadAllBytes("..\\text.txt");

	auto res = Encrypt(key, data);

	return 0;
}