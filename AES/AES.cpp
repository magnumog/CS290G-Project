#include "stdafx.h"
#include "AES.h"
#include "KeySchedule.h"
#include "Rijndael.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <vector>
#include <cassert>
#include <string.h>
#include <stdio.h>
using namespace std;

// https://github.com/kokke/tiny-AES128-C/blob/master/aes.c

// http://www.codeproject.com/Articles/1380/A-C-Implementation-of-the-Rijndael-Encryption-Decr
// http://en.wikipedia.org/wiki/Rijndael_key_schedule
// http://en.wikipedia.org/wiki/Rijndael_S-box
// http://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael.27s_finite_field

#define SR(i, j) result2[i] = result[j];

#define ShiftRowInverse(i,j) temp[i] = temp2[i];

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

static uint8_t hex2byte(const char* hex)
{
	unsigned short byte = 0;
	std::istringstream iss(hex);
	iss >> std::hex >> byte;
	return byte % 0x100;
}

static vector<vector<uint8_t>> FileReadAllBytes(char const* filename)
{
	ifstream ifs(filename, ios::binary);

	vector<vector<uint8_t>> result;

	std::string line;
	while (std::getline(ifs, line))
	{
		if (line.length() != 16) continue;

		vector<uint8_t> innerResult(16);

		for (auto i = 0; i < 16; i++)
		{
			char c[2];
			strncpy_s(c, &line[i], 1);
			innerResult[i] = hex2byte(c);
		}

		result.push_back(innerResult);
	}

	return result;
}

static vector<uint8_t> Encrypt(vector<uint8_t> key, vector<uint8_t> data)
{
	//key[0] =  0x54;
	//key[1] =  0x68;
	//key[2] =  0x61;
	//key[3] =  0x74;
	//key[4] =  0x73;
	//key[5] =  0x20;
	//key[6] =  0x6D;
	//key[7] =  0x79;
	//key[8] =  0x20;
	//key[9] =  0x4B;
	//key[10] = 0x75;
	//key[11] = 0x6E;
	//key[12] = 0x67;
	//key[13] = 0x20;
	//key[14] = 0x46;
	//key[15] = 0x75;
	//
	//
	//data[0] =  0x54;
	//data[1] =  0x77;
	//data[2] =  0x6F;
	//data[3] =  0x20;
	//data[4] =  0x4F;
	//data[5] =  0x6E;
	//data[6] =  0x65;
	//data[7] =  0x20;
	//data[8] =  0x4E;
	//data[9] =  0x69;
	//data[10] = 0x6E;
	//data[11] = 0x65;
	//data[12] = 0x20;
	//data[13] = 0x54;
	//data[14] = 0x77;
	//data[15] = 0x6F;






	KeySchedule keySchedule(key);

	auto firstKey = keySchedule.GetNextKey();
	auto tmp = vector<uint8_t>(16);

	for (auto i = 0; i < 16; i++)
	{
		tmp[i] = firstKey[i] ^ data[i];
	}

	// 1 to n-1 rounds
	for (auto i = 0; i < 9; i++)
	{
		// sbox
		auto sboxTmp = vector<uint8_t>(16);
		for (auto i = 0; i < 16; i++)
		{
			sboxTmp[i] = sbox[tmp[i]];
		}

		// shift rows / mix column
		auto mcTmp = vector<uint8_t>(16);
		MC(0, 0, 5, 10, 15)
		MC(4, 4, 9, 14, 3)
		MC(8, 8, 13, 2, 7)
		MC(12, 12, 1, 6, 11)

		// add key
		auto newKey = keySchedule.GetNextKey();
		for (auto i = 0; i < 16; i++)
		{
			tmp[i] = newKey[i] ^ mcTmp[i];
		}
	}
	

	auto result = vector<uint8_t>(16);
	auto result2 = vector<uint8_t>(16);

	// sbox
	for (auto i = 0; i < 16; i++)
	{
		result[i] = sbox[tmp[i]];
	}

	// shift rows
	SR(0,0)
	SR(1,5)
	SR(2,10)
	SR(3,15)
	SR(4,4)
	SR(5,9)
	SR(6,14)
	SR(7,3)
	SR(8,8)
	SR(9,13)
	SR(10,2)
	SR(11,7)
	SR(12,12)
	SR(13,1)
	SR(14,6)
	SR(15,11)

	// add key
	auto newKey = keySchedule.GetNextKey();
	for (auto i = 0; i < 16; i++)
	{
		tmp[i] = newKey[i] ^ result2[i];
	}
	
	
	return tmp;
}

static vector<uint8_t> decrypt(vector<uint8_t> key, vector<uint8_t> message) {
	KeySchedule keySchedule(key);

	auto firstKey = keySchedule.GetNextKey;
	auto temp = vector<uint8_t>(16);
	auto temp2 = vector<uint8_t>(16);
	for(auto i=0;i<16;i++) {
		temp2[i] = firstKey^data[i];
	}

	SR(0,0)
	SR(1,1)
	SR(2,2)
	SR(3,3)
	SR(4,7)
	SR(5,4)
	SR(6,5)
	SR(7,6)
	SR(8,10)
	SR(9,11)
	SR(10,8)
	SR(11,9)
	SR(12,13)
	SR(13,14)
	SR(14,15)
	SR(15,12)

	auto sboxTemp = vector<uint8_t>(16);
	for (auto i = 0; i < 16; i++) {
		sboxTemp[i] = rsbox[temp[i]];
	}
	//DO I NEED TO MULTIPLY THE SBOXTEMP WITH TEMP??

	//2 to n rounds
	for(auto i=0;i<9;i++) {
		auto newKey = keySchedule.GetNextKey();
		for(auto i=0;i<16;i++) {
			temp[i] = newKey[i]^mc_InvTmp[i];
		}

		//InverseMixColumns
		auto mc_InvTmp = vector<uint8_t>(16);
		MC_inv(0,0,4,8,12);
		MC_inv(4,13,1,5,9);
		MC_inv(8,10,14,2,6);
		MC_inv(12,7,11,15,3)

		for (auto i = 0; i < 16; i++) {
			sboxTemp[i] = rsbox[temp[i]];
		}
		//DO I NEED TO MULTIPLY THE SBOXTEMP WITH TEMP??
	}

	auto newKey = keySchedule.GetNextKey();
	for(auto i=0;i<16;i++) {
		temp[i] = newKey[i]^temp[i]
	}
	return temp;

}



int _tmain(int argc, _TCHAR* argv[])
{
	assert(hex2byte("") == 0);
	assert(hex2byte("00") == 0);
	assert(hex2byte("A") == 10);
	assert(hex2byte("0A") == 10);
	assert(hex2byte("FF") == 255);
	assert(hex2byte("EEFF") == 255);
	assert(hex2byte("GG") == 00);
	assert(hex2byte("a") == 10);
	assert(hex2byte("0a") == 10);
	assert(hex2byte("f3") == 243);
	assert(hex2byte("ff") == 255);
	assert(hex2byte("eeff") == 255);
	assert(hex2byte("gg") == 00);

	auto key = FileReadAllBytes("..\\key.txt");
	auto data = FileReadAllBytes("..\\text.txt");

	for (auto it = data.begin(); it != data.end(); it++)
	{
		auto res = Encrypt(key[0], *it);
	}
	
	return 0;
}
