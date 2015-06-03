#pragma once
#include <vector>;
#include <stdint.h>

class KeySchedule
{
	int m_currentRoundNum = 0;
	std::vector<uint8_t> m_currentRoundKey;

public:
	KeySchedule(std::vector<uint8_t> key);
	~KeySchedule();
	std::vector<uint8_t> GetNextKey();
	std::vector<std::vector<uint8_t>> CreateKeys(std::vector<uint8_t> key, int num);
};