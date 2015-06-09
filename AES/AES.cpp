#include "AES.h"
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


/* Key schedule generation
 */
#define KeyRotate(arr, offset) {					\
	arr[offset+4] = arr[offset+4] ^ arr[offset];	\
	arr[offset+5] = arr[offset+5] ^ arr[offset+1];	\
	arr[offset+6] = arr[offset+6] ^ arr[offset+2];	\
	arr[offset+7] = arr[offset+7] ^ arr[offset+3];	\
}

std::vector<std::vector<uint8_t> > CreateKeys(std::vector<uint8_t> key, int num)
{
	auto keyArray = std::vector<std::vector<uint8_t> >(num);
	keyArray[0] = key;

	for (auto i = 1; i < num; i++)
	{
		auto roundKey = std::vector<uint8_t>(keyArray[i - 1]);
		uint8_t* ptr = roundKey.data();

		// first 4 bytes with g applied
		ptr[0] = ptr[0] ^ (SBOX[ptr[13]] ^ Rcon[i]);
		ptr[1] = ptr[1] ^ SBOX[ptr[14]];
		ptr[2] = ptr[2] ^ SBOX[ptr[15]];
		ptr[3] = ptr[3] ^ SBOX[ptr[12]];

		// last 12 bytes
		KeyRotate(ptr, 0);
		KeyRotate(ptr, 4);
		KeyRotate(ptr, 8);

		keyArray[i] = roundKey;
	}

	// Return current key
	return keyArray;
}



/* File reading
 */
static uint8_t HexToByte(const char* hex)
{
	unsigned short byte = 0;
	std::istringstream iss(hex);
	iss >> std::hex >> byte;
	return byte % 0x100;
}

static vector<vector<uint8_t> > FileReadAllBytes(char const* filename)
{
	ifstream ifs(filename, ios::binary);

	vector<vector<uint8_t> > retArray;

	std::string line;
	while (std::getline(ifs, line))
	{
		if (line.length() != 32) continue;

		vector<uint8_t> lineBytes(16);

		for (auto i = 0; i < 16; i++)
		{
			char c[3];
			strncpy(c, &line[i * 2], 2);
			lineBytes[i] = HexToByte(c);
		}

		retArray.push_back(lineBytes);
	}

	return retArray;
}



/* Encryption
 */
#define ShiftRows(arrIn, arrOut, i, j) arrOut[i] = arrIn[j];

#define MixColumns(arrIn, arrOut, i, j0, j1, j2, j3) {						            \
	arrOut[i] = (uint8_t)(GF2[arrIn[j0]] ^ GF3[arrIn[j1]] ^ arrIn[j2] ^ arrIn[j3]);	    \
	arrOut[i+1] = (uint8_t)(arrIn[j0] ^ GF2[arrIn[j1]] ^ GF3[arrIn[j2]] ^ arrIn[j3]);	\
	arrOut[i+2] = (uint8_t)(arrIn[j0] ^ arrIn[j1] ^ GF2[arrIn[j2]] ^ GF3[arrIn[j3]]);	\
	arrOut[i+3] = (uint8_t)(GF3[arrIn[j0]] ^ arrIn[j1] ^ arrIn[j2] ^ GF2[arrIn[j3]]);	\
}

static vector<uint8_t> Encrypt(vector<uint8_t> key, vector<uint8_t> data)
{
	// create 11 keys for 128bit key profile
	auto keys = CreateKeys(key, 11);
	
	// two temporary arrays of 128bit / 16 bytes needed
	auto tmp1 = vector<uint8_t>(16);
	auto tmp2 = vector<uint8_t>(16);

	// initialize with AddKey
	auto firstKey = keys[0];
	for (auto i = 0; i < 16; i++)
	{
		tmp1[i] = firstKey[i] ^ data[i];
	}

	// 1 to n-1 rounds
	for (auto i = 0; i < 9; i++)
	{
		// ByteSub
		for (auto i = 0; i < 16; i++)
		{
			tmp2[i] = SBOX[tmp1[i]];
		}

		// ShiftRows / MixColumns
		MixColumns(tmp2, tmp1, 0, 0, 5, 10, 15)
		MixColumns(tmp2, tmp1, 4, 4, 9, 14, 3)
		MixColumns(tmp2, tmp1, 8, 8, 13, 2, 7)
		MixColumns(tmp2, tmp1, 12, 12, 1, 6, 11)

		// AddKey
		auto roundKey = keys[i+1];
		for (auto i = 0; i < 16; i++)
		{
			tmp1[i] = roundKey[i] ^ tmp1[i];
		}
	}

	// last round onwards
	
	// ByteSub
	for (auto i = 0; i < 16; i++)
	{
		tmp2[i] = SBOX[tmp1[i]];
	}

	// ShiftRows
	ShiftRows(tmp2, tmp1, 0,0)
	ShiftRows(tmp2, tmp1, 1,5)
	ShiftRows(tmp2, tmp1, 2,10)
	ShiftRows(tmp2, tmp1, 3,15)
	ShiftRows(tmp2, tmp1, 4,4)
	ShiftRows(tmp2, tmp1, 5,9)
	ShiftRows(tmp2, tmp1, 6,14)
	ShiftRows(tmp2, tmp1, 7,3)
	ShiftRows(tmp2, tmp1, 8,8)
	ShiftRows(tmp2, tmp1, 9,13)
	ShiftRows(tmp2, tmp1, 10,2)
	ShiftRows(tmp2, tmp1, 11,7)
	ShiftRows(tmp2, tmp1, 12,12)
	ShiftRows(tmp2, tmp1, 13,1)
	ShiftRows(tmp2, tmp1, 14,6)
	ShiftRows(tmp2, tmp1, 15,11)

	// AddKey
	auto lastKey = keys[10];
	for (auto i = 0; i < 16; i++)
	{
		tmp2[i] = lastKey[i] ^ tmp1[i];
	}
	
	
	return tmp2;
}



/* Decryption
 */
#define ShiftRowsInverse(arrIn, arrOut, i,j) arrOut[i] = arrIn[j];

#define MixColumnsInverse(arrIn, arrOut, i,j0,j1,j2,j3) {																\
	arrOut[i] = (uint8_t)(GF14[arrIn[i]] ^ GF11[arrIn[i+1 ]] ^ GF13[arrIn[i+2]] ^ GF9[arrIn [i+3]]);	\
	arrOut[i+1] = (uint8_t)(GF9[arrIn[i]] ^ GF14[arrIn[i+1]] ^ GF11[arrIn[i+2]] ^ GF13[arrIn[i+3]]);	\
	arrOut[i+2] = (uint8_t)(GF13[arrIn[i]] ^ GF9[arrIn[i+1]] ^ GF14[arrIn[i+2]] ^ GF11[arrIn[i+3]]);	\
	arrOut[i+3] = (uint8_t)(GF11[arrIn[i]] ^ GF13[arrIn[i+1]] ^ GF9[arrIn[i+2]] ^ GF14[arrIn[i+3]]);	\
}

static vector<uint8_t> Decrypt(vector<uint8_t> key, vector<uint8_t> data) {

	// create 11 keys for 128bit key profile - use them in reverse order
	auto keys = CreateKeys(key, 11);
	reverse(keys.begin(), keys.end());
	
	// two temporary arrays of 128bit / 16 bytes needed
	auto tmp1 = vector<uint8_t>(16);
	auto tmp2 = vector<uint8_t>(16);

	// AddKey
	auto firstKey = keys[0];
	for(auto i=0;i<16;i++)
	{
		tmp2[i] = firstKey[i] ^ data[i];
	}

	// inverse ShiftRows
	ShiftRowsInverse(tmp2, tmp1, 0, 0);
	ShiftRowsInverse(tmp2, tmp1, 1, 13);
	ShiftRowsInverse(tmp2, tmp1, 2, 10);
	ShiftRowsInverse(tmp2, tmp1, 3, 7);
	ShiftRowsInverse(tmp2, tmp1, 4, 4);
	ShiftRowsInverse(tmp2, tmp1, 5, 1);
	ShiftRowsInverse(tmp2, tmp1, 6, 14);
	ShiftRowsInverse(tmp2, tmp1, 7, 11);
	ShiftRowsInverse(tmp2, tmp1, 8, 8);
	ShiftRowsInverse(tmp2, tmp1, 9, 5);
	ShiftRowsInverse(tmp2, tmp1, 10, 2);
	ShiftRowsInverse(tmp2, tmp1, 11, 15);
	ShiftRowsInverse(tmp2, tmp1, 12, 12);
	ShiftRowsInverse(tmp2, tmp1, 13, 9);
	ShiftRowsInverse(tmp2, tmp1, 14, 6);
	ShiftRowsInverse(tmp2, tmp1, 15, 3);

	// inverse ByteSub
	for (auto i = 0; i < 16; i++)
	{
		tmp2[i] = INVSBOX[tmp1[i]];
	}

	// 2 to n rounds
	for(auto i=1;i<10;i++)
	{
		// AddKey
		auto roundKey = keys[i];
		for (auto j = 0; j<16; j++) {
			tmp1[j] = tmp2[j] ^ roundKey[j];
		}

		// inverse MixColumns
		MixColumnsInverse(tmp1, tmp2, 0,0,13,10,7);
		MixColumnsInverse(tmp1, tmp2, 4,4,1,14,11);
		MixColumnsInverse(tmp1, tmp2, 8,8,5,2,15);
		MixColumnsInverse(tmp1, tmp2, 12,12,9,6,3);

		// inverse ShiftRows
		ShiftRowsInverse(tmp2, tmp1, 0, 0);
		ShiftRowsInverse(tmp2, tmp1, 1, 13);
		ShiftRowsInverse(tmp2, tmp1, 2, 10);
		ShiftRowsInverse(tmp2, tmp1, 3, 7);
		ShiftRowsInverse(tmp2, tmp1, 4, 4);
		ShiftRowsInverse(tmp2, tmp1, 5, 1);
		ShiftRowsInverse(tmp2, tmp1, 6, 14);
		ShiftRowsInverse(tmp2, tmp1, 7, 11);
		ShiftRowsInverse(tmp2, tmp1, 8, 8);
		ShiftRowsInverse(tmp2, tmp1, 9, 5);
		ShiftRowsInverse(tmp2, tmp1, 10, 2);
		ShiftRowsInverse(tmp2, tmp1, 11, 15);
		ShiftRowsInverse(tmp2, tmp1, 12, 12);
		ShiftRowsInverse(tmp2, tmp1, 13, 9);
		ShiftRowsInverse(tmp2, tmp1, 14, 6);
		ShiftRowsInverse(tmp2, tmp1, 15, 3);
		
		// inverse ByteSub
		for (auto j = 0; j < 16; j++) {
			tmp2[j] = INVSBOX[tmp1[j]];
		}
	}

	// AddKey
	auto lastKey = keys[10];
	for(auto i=0;i<16;i++)
	{
		tmp1[i] = tmp2[i] ^ lastKey[i];
	}


	return tmp1;
}



/* Program entry point
 */
int main()
{
	// read key and messages to encrypt
	auto keys = FileReadAllBytes("key.txt");
	auto messages = FileReadAllBytes("messages.txt");

	// key / file setup
	auto key = keys[0]; // same key for all messages
	ofstream myfile;
	myfile.open("output.txt");

	// loop all messages
	for (auto it = messages.begin(); it != messages.end(); it++)
	{
		auto ciphertext = Encrypt(key, *it);
		//auto cleartext = Decrypt(key, res);

		// output ciphertext to file in HEX format
		for (auto i = 0; i < 16; i++)
		{
			myfile << hex << setfill('0') << setw(2) << (int)ciphertext[i] << "";
		}
		myfile << endl;
	}

	myfile.close();
	
	return 0;
}