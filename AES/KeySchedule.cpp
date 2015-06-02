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

#define OP(arr, offset) {							\
	arr[offset+4] = arr[offset+4] ^ arr[offset];	\
	arr[offset+5] = arr[offset+5] ^ arr[offset+1];	\
	arr[offset+6] = arr[offset+6] ^ arr[offset+2];	\
	arr[offset+7] = arr[offset+7] ^ arr[offset+3];	\
}

std::vector<uint8_t> KeySchedule::GetNextKey()
{
	auto retKey = std::vector<uint8_t>(m_currentRoundKey);

	// calculate key for next round
	uint8_t* ptr = m_currentRoundKey.data();

	// first 4 bytes with g applied
	ptr[0] = ptr[0] ^ (sbox[ptr[13]] ^ Rcon[m_currentRoundNum+1]);
	ptr[1] = ptr[1] ^ sbox[ptr[14]];
	ptr[2] = ptr[2] ^ sbox[ptr[15]];
	ptr[3] = ptr[3] ^ sbox[ptr[12]];

	// last 12 bytes
	OP(ptr, 0);
	OP(ptr, 4);
	OP(ptr, 8);

	// advance roundNo for next round
	m_currentRoundNum++;

	// Return current key
	return retKey;
}