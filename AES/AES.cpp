#include "stdafx.h"
#include "AES.h"
#include "KeySchedule.h"
#include <iostream>
#include <fstream>
#include <memory>
#include <vector>
using namespace std;

static vector<char> FileReadAllBytes(char const* filename)
{
	ifstream ifs(filename, ios::binary | ios::ate);

	ifstream::pos_type pos = ifs.tellg();

	vector<char>  result(pos);

	ifs.seekg(0, ios::beg);
	ifs.read(&result[0], pos);

	return result;
}

static vector<char> Encrypt(vector<char> key, vector<char> data)
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