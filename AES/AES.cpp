// AES.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <vector>
#include <math.h>
#include <iostream>
#include <fstream>
#include <memory>

using namespace std;


int _tmain(int argc, _TCHAR* argv[])
{
	vector<int> arr;

	int length;
	auto text = ReadAllBytes("", &length);

	return 0;
}


static shared_ptr<char*> ReadAllBytes(const char* filename, int* read)
{
	ifstream ifs(filename, ios::binary | ios::ate);
	ifstream::pos_type pos = ifs.tellg();
	int length = pos;
	char* pChars = new char[length];
	ifs.seekg(0, ios::beg);
	ifs.read(pChars, length);
	ifs.close();
	*read = length;
	return make_shared<char*>(pChars);
}

