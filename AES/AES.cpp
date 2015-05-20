#include "stdafx.h"
#include "AES.h"
#include "KeySchedule.h"
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

static vector<uint8_t> FileReadAllBytes(char const* filename)
{
	ifstream ifs(filename, ios::binary | ios::ate);

	ifstream::pos_type pos = ifs.tellg();

	vector<uint8_t> result(pos);

	ifs.seekg(0, ios::beg);
	ifs.read((char*)&result[0], pos);

	return result;
}

static vector<char> Encrypt(vector<uint8_t> key, vector<uint8_t> data)
{
	KeySchedule keySchedule(key);

	auto newKey = keySchedule.NextKey();
}

int _tmain(int argc, _TCHAR* argv[])
{
	auto key = FileReadAllBytes("..\\key.txt");
	auto text = FileReadAllBytes("..\\text.txt");

	return 0;
}