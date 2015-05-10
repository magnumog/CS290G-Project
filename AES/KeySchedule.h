#pragma once
#include <vector>;

class KeySchedule
{
public:
	KeySchedule(std::vector<char> key);
	~KeySchedule();
	std::vector<char> NextKey();
};