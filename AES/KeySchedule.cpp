#include "KeySchedule.h"
#include "Rijndael.h"
#include <array>


KeySchedule::KeySchedule(std::vector<uint8_t> key)
{
	m_currentRoundKey = key;
}


KeySchedule::~KeySchedule()
{
}

