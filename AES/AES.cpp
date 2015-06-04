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
#include <algorithm>
#include <iomanip>
using namespace std;

// https://github.com/kokke/tiny-AES128-C/blob/master/aes.c

// http://www.codeproject.com/Articles/1380/A-C-Implementation-of-the-Rijndael-Encryption-Decr
// http://en.wikipedia.org/wiki/Rijndael_key_schedule
// http://en.wikipedia.org/wiki/Rijndael_S-box
// http://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael.27s_finite_field

#define SR(i, j) result2[i] = result[j];

#define ShiftRowInverse(i,j) temp[i] = temp2[j];

#define MC(i, j0, j1, j2, j3) {						            \
	mcTmp[i] = (uint8_t)(galois2[sboxTmp[j0]] ^ galois3[sboxTmp[j1]] ^ sboxTmp[j2] ^ sboxTmp[j3]);	    \
	mcTmp[i+1] = (uint8_t)(sboxTmp[j0] ^ galois2[sboxTmp[j1]] ^ galois3[sboxTmp[j2]] ^ sboxTmp[j3]);	\
	mcTmp[i+2] = (uint8_t)(sboxTmp[j0] ^ sboxTmp[j1] ^ galois2[sboxTmp[j2]] ^ galois3[sboxTmp[j3]]);	\
	mcTmp[i+3] = (uint8_t)(galois3[sboxTmp[j0]] ^ sboxTmp[j1] ^ sboxTmp[j2] ^ galois2[sboxTmp[j3]]);	\
}

#define MC_inv(i,j0,j1,j2,j3) {																										\
	temp2[i] = (uint8_t)(galois14[temp[i]] ^ galois11[temp[i+1 ]] ^ galois13[temp[i+2]] ^ galois9[temp [i+3]]);		\
	temp2[i+1] = (uint8_t)(galois9[temp[i]] ^ galois14[temp[i+1]] ^ galois11[temp[i+2]] ^ galois13[temp[i+3]]);	\
	temp2[i+2] = (uint8_t)(galois13[temp[i]] ^ galois9[temp[i+1]] ^ galois14[temp[i+2]] ^ galois11[temp[i+3]]);	\
	temp2[i+3] = (uint8_t)(galois11[temp[i]] ^ galois13[temp[i+1]] ^ galois9[temp[i+2]] ^ galois14[temp[i+3]]);	\
}

static uint8_t hex2byte(const char* hex)
{
	unsigned short byte = 0;
	std::istringstream iss(hex);
	iss >> std::hex >> byte;
	return byte % 0x100;
}

static vector<vector<uint8_t> > FileReadAllBytes(char const* filename)
{
	ifstream ifs(filename, ios::binary);

	vector<vector<uint8_t> > result;

	std::string line;
	while (std::getline(ifs, line))
	{
		if (line.length() != 32) continue;

		vector<uint8_t> innerResult(16);

		for (auto i = 0; i < 16; i++)
		{
			char c[3];
			strncpy_s(c, &line[i*2], 2);
			innerResult[i] = hex2byte(c);
		}

		result.push_back(innerResult);
	}

	return result;
}

static vector<uint8_t> Encrypt(vector<uint8_t> key, vector<uint8_t> data)
{
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

static vector<uint8_t> Decrypt(vector<uint8_t> key, vector<uint8_t> data) {

	// generate keys
	KeySchedule keySchedule(key);
	auto keys = keySchedule.CreateKeys(key, 11);
	reverse(keys.begin(), keys.end());
	
	
	auto temp = vector<uint8_t>(16);
	auto temp2 = vector<uint8_t>(16);

	// key addition
	auto roundKey = keys[0];
	for(auto i=0;i<16;i++) {
		temp2[i] = roundKey[i] ^ data[i];
	}

	// inverse shift rows
	ShiftRowInverse(0, 0);
	ShiftRowInverse(1, 13);
	ShiftRowInverse(2, 10);
	ShiftRowInverse(3, 7);
	ShiftRowInverse(4, 4);
	ShiftRowInverse(5, 1);
	ShiftRowInverse(6, 14);
	ShiftRowInverse(7, 11);
	ShiftRowInverse(8, 8);
	ShiftRowInverse(9, 5);
	ShiftRowInverse(10, 2);
	ShiftRowInverse(11, 15);
	ShiftRowInverse(12, 12);
	ShiftRowInverse(13, 9);
	ShiftRowInverse(14, 6);
	ShiftRowInverse(15, 3);

	// inverse byte substitution
	for (auto i = 0; i < 16; i++) {
		temp2[i] = rsbox[temp[i]];
	}

	//2 to n rounds
	for(auto i=1;i<10;i++) {
		// key addition
		auto roundKey = keys[i];
		for (auto j = 0; j<16; j++) {
			temp[j] = temp2[j] ^ roundKey[j];
		}

		// inverse shift rows / InverseMixColumns
		MC_inv(0,0,13,10,7);
		MC_inv(4,4,1,14,11);
		MC_inv(8,8,5,2,15);
		MC_inv(12,12,9,6,3);

		// inverse shift rows
		ShiftRowInverse(0, 0);
		ShiftRowInverse(1, 13);
		ShiftRowInverse(2, 10);
		ShiftRowInverse(3, 7);
		ShiftRowInverse(4, 4);
		ShiftRowInverse(5, 1);
		ShiftRowInverse(6, 14);
		ShiftRowInverse(7, 11);
		ShiftRowInverse(8, 8);
		ShiftRowInverse(9, 5);
		ShiftRowInverse(10, 2);
		ShiftRowInverse(11, 15);
		ShiftRowInverse(12, 12);
		ShiftRowInverse(13, 9);
		ShiftRowInverse(14, 6);
		ShiftRowInverse(15, 3);
		
		// invert byte substitution
		for (auto j = 0; j < 16; j++) {
			temp2[j] = rsbox[temp[j]];
		}
	}

	// key addition
	roundKey = keys[10];
	for(auto i=0;i<16;i++) {
		temp[i] = temp2[i] ^ roundKey[i];
	}

	return temp;
}







int main()
{
	auto keys = FileReadAllBytes("key.txt");
	auto messages = FileReadAllBytes("messages.txt");

	auto key = keys[0];

	ofstream myfile;
	myfile.open("output.txt");

	for (auto it = messages.begin(); it != messages.end(); it++)
	{
		auto res = Encrypt(key, *it);
		//auto res2 = Decrypt(key, res);

		for (auto i = 0; i < 16; i++)
		{
			myfile << hex << setfill('0') << setw(2) << (int)res[i] << "";
		}
		myfile << endl;
	}

	myfile.close();
	
	return 0;
}