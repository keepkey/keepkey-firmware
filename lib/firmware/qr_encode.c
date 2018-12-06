/*
 * Copyright (c) 2010 Psytec Inc.
 * Copyright (c) 2012 Alexey Mednyy <swexru@gmail.com>
 * Copyright (c) 2012-2014 Pavol Rusnak <stick@gk2.sk>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#include "keepkey/firmware/qr_encode.h"
#include "keepkey/firmware/qr_consts.h"

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>


int m_nLevel;
int m_nVersion;
int m_nMaskingNo;
int m_ncDataCodeWordBit, m_ncAllCodeWord, nEncodeVersion;
int m_ncDataBlock;
int m_nSymbleSize;
int m_nBlockLength[QR_MAX_DATACODEWORD];
uint8_t m_byModuleData[QR_MAX_MODULESIZE][QR_MAX_MODULESIZE]; // [x][y]
uint8_t m_byAllCodeWord[QR_MAX_ALLCODEWORD];
uint8_t m_byBlockMode[QR_MAX_DATACODEWORD];
uint8_t m_byDataCodeWord[QR_MAX_DATACODEWORD];
uint8_t m_byRSWork[QR_MAX_CODEBLOCK];


int IsNumeralData(uint8_t c)
{
	if (c >= '0' && c <= '9') return 1;
	return 0;
}

int IsAlphabetData(uint8_t c)
{
	if (c >= '0' && c <= '9') return 1;
	if (c >= 'A' && c <= 'Z') return 1;
	if (c == ' ' || c == '$' || c == '%' || c == '*' || c == '+' || c == '-' || c == '.' || c == '/' || c == ':') return 1;
	return 0;
}

uint8_t AlphabetToBinary(uint8_t c)
{
	if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
	if (c >= 'A' && c <= 'Z') return (uint8_t)(c - 'A' + 10);
	if (c == ' ') return 36;
	if (c == '$') return 37;
	if (c == '%') return 38;
	if (c == '*') return 39;
	if (c == '+') return 40;
	if (c == '-') return 41;
	if (c == '.') return 42;
	if (c == '/') return 43;
	return 44; // c == ':'
}

int SetBitStream(int nIndex, uint16_t wData, int ncData)
{
	int i;
	if (nIndex == -1 || nIndex + ncData > QR_MAX_DATACODEWORD * 8) return -1;
	for (i = 0; i < ncData; i++) {
		if (wData & (1 << (ncData - i - 1))) {
			m_byDataCodeWord[(nIndex + i) / 8] |= 1 << (7 - ((nIndex + i) % 8));
		}
	}
	return nIndex + ncData;
}

int GetBitLength(uint8_t nMode, int ncData, int nVerGroup)
{
	int ncBits = 0;
	switch (nMode) {
		case QR_MODE_NUMERAL:
			ncBits = 4 + nIndicatorLenNumeral[nVerGroup] + (10 * (ncData / 3));
			switch (ncData % 3) {
				case 1:
					ncBits += 4;
					break;
				case 2:
					ncBits += 7;
					break;
				default: // case 0:
					break;
			}
			break;
		case QR_MODE_ALPHABET:
			ncBits = 4 + nIndicatorLenAlphabet[nVerGroup] + (11 * (ncData / 2)) + (6 * (ncData % 2));
			break;
		default: // case QR_MODE_8BIT:
			ncBits = 4 + nIndicatorLen8Bit[nVerGroup] + (8 * ncData);
			break;
	}
	return ncBits;
}

int EncodeSourceData(const char* lpsSource, int ncLength, int nVerGroup)
{
	memset(m_nBlockLength, 0, sizeof(m_nBlockLength));
	int i, j;
	// Investigate whether continuing characters (bytes) which mode is what
	for (m_ncDataBlock = i = 0; i < ncLength; i++) {
		uint8_t byMode;
		if (IsNumeralData(lpsSource[i])) {
			byMode = QR_MODE_NUMERAL;
		} else if (IsAlphabetData(lpsSource[i])) {
			byMode = QR_MODE_ALPHABET;
		} else {
			byMode = QR_MODE_8BIT;
		}
		if (i == 0) {
			m_byBlockMode[0] = byMode;
		}
		if (m_byBlockMode[m_ncDataBlock] != byMode) {
			m_byBlockMode[++m_ncDataBlock] = byMode;
		}
		m_nBlockLength[m_ncDataBlock]++;
	}
	m_ncDataBlock++;

	// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
	// Linked by a sequence of conditional block alphanumeric mode and numeric mode block adjacent

	int ncSrcBits, ncDstBits; // The bit length of the block mode if you have over the original bit length and a single alphanumeric
	int nBlock = 0;

	while (nBlock < m_ncDataBlock - 1) {
		int ncJoinFront, ncJoinBehind; 		// Bit length when combined with 8-bit byte block mode before and after
		int nJoinPosition = 0; 		// Block the binding of 8-bit byte mode: combined with the previous -1 = 0 = do not bind, bind behind a =

		// Sort of - "digit alphanumeric" - "or alphanumeric numbers"
		if ((m_byBlockMode[nBlock] == QR_MODE_NUMERAL && m_byBlockMode[nBlock + 1] == QR_MODE_ALPHABET) ||
			(m_byBlockMode[nBlock] == QR_MODE_ALPHABET && m_byBlockMode[nBlock + 1] == QR_MODE_NUMERAL)) {

			// If you compare the bit length of alphanumeric characters and a single block mode over the original bit length
			ncSrcBits = GetBitLength(m_byBlockMode[nBlock], m_nBlockLength[nBlock], nVerGroup) +
						GetBitLength(m_byBlockMode[nBlock + 1], m_nBlockLength[nBlock + 1], nVerGroup);

			ncDstBits = GetBitLength(QR_MODE_ALPHABET, m_nBlockLength[nBlock] + m_nBlockLength[nBlock + 1], nVerGroup);

			if (ncSrcBits > ncDstBits) {
				// If there is an 8-bit byte block mode back and forth, check whether they favor the binding of
				if (nBlock >= 1 && m_byBlockMode[nBlock - 1] == QR_MODE_8BIT) {
					// There are 8-bit byte block mode before
					ncJoinFront = GetBitLength(QR_MODE_8BIT, m_nBlockLength[nBlock - 1] + m_nBlockLength[nBlock], nVerGroup) +
								GetBitLength(m_byBlockMode[nBlock + 1], m_nBlockLength[nBlock + 1], nVerGroup);

					if (ncJoinFront > ncDstBits + GetBitLength(QR_MODE_8BIT, m_nBlockLength[nBlock - 1], nVerGroup)) {
						ncJoinFront = 0; // 8-bit byte and block mode does not bind
					}
				} else {
					ncJoinFront = 0;
				}

				if (nBlock < m_ncDataBlock - 2 && m_byBlockMode[nBlock + 2] == QR_MODE_8BIT) {
					// There are 8-bit byte mode block behind
					ncJoinBehind = GetBitLength(m_byBlockMode[nBlock], m_nBlockLength[nBlock], nVerGroup) +
								GetBitLength(QR_MODE_8BIT, m_nBlockLength[nBlock + 1] + m_nBlockLength[nBlock + 2], nVerGroup);

					if (ncJoinBehind > ncDstBits + GetBitLength(QR_MODE_8BIT, m_nBlockLength[nBlock + 2], nVerGroup)) {
						ncJoinBehind = 0; // 8-bit byte and block mode does not bind
					}
				} else {
					ncJoinBehind = 0;
				}

				if (ncJoinFront != 0 && ncJoinBehind != 0) {
					// If there is a 8-bit byte block mode has priority both before and after the way the data length is shorter
					nJoinPosition = (ncJoinFront < ncJoinBehind) ? -1 : 1;
				} else {
					nJoinPosition = (ncJoinFront != 0) ? -1 : ((ncJoinBehind != 0) ? 1 : 0);
				}

				if (nJoinPosition != 0) {
					// Block the binding of 8-bit byte mode
					if (nJoinPosition == -1) {
						m_nBlockLength[nBlock - 1] += m_nBlockLength[nBlock];

						// The subsequent shift
						for (i = nBlock; i < m_ncDataBlock - 1; i++) {
							m_byBlockMode[i] = m_byBlockMode[i + 1];
							m_nBlockLength[i] = m_nBlockLength[i + 1];
						}
					} else {
						m_byBlockMode[nBlock + 1] = QR_MODE_8BIT;
						m_nBlockLength[nBlock + 1] += m_nBlockLength[nBlock + 2];

						// The subsequent shift
						for (i = nBlock + 2; i < m_ncDataBlock - 1; i++) {
							m_byBlockMode[i] = m_byBlockMode[i + 1];
							m_nBlockLength[i] = m_nBlockLength[i + 1];
						}
					}

					m_ncDataBlock--;
				} else {
				// Block mode integrated into a single alphanumeric string of numbers and alphanumeric

					if (nBlock < m_ncDataBlock - 2 && m_byBlockMode[nBlock + 2] == QR_MODE_ALPHABET) {
						// Binding mode of the block followed by alphanumeric block attempts to join
						m_nBlockLength[nBlock + 1] += m_nBlockLength[nBlock + 2];

						// The subsequent shift
						for (i = nBlock + 2; i < m_ncDataBlock - 1; i++) {
							m_byBlockMode[i] = m_byBlockMode[i + 1];
							m_nBlockLength[i] = m_nBlockLength[i + 1];
						}

						m_ncDataBlock--;
					}

					m_byBlockMode[nBlock] = QR_MODE_ALPHABET;
					m_nBlockLength[nBlock] += m_nBlockLength[nBlock + 1];

					// The subsequent shift
					for (i = nBlock + 1; i < m_ncDataBlock - 1; i++) {
						m_byBlockMode[i] = m_byBlockMode[i + 1];
						m_nBlockLength[i] = m_nBlockLength[i + 1];
					}

					m_ncDataBlock--;

					if (nBlock >= 1 && m_byBlockMode[nBlock - 1] == QR_MODE_ALPHABET) {

						// Combined mode of alphanumeric block before the block bound
						m_nBlockLength[nBlock - 1] += m_nBlockLength[nBlock];

						// The subsequent shift
						for (i = nBlock; i < m_ncDataBlock - 1; i++) {
							m_byBlockMode[i] = m_byBlockMode[i + 1];
							m_nBlockLength[i] = m_nBlockLength[i + 1];
						}

						m_ncDataBlock--;
					}
				}

				continue;
				// Re-examine the block of the current position
			}
		}

		nBlock++; // Investigate the next block
	}

	// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
	// 8-bit byte block mode over the short block mode to continuous

	nBlock = 0;

	while (nBlock < m_ncDataBlock - 1) {
		ncSrcBits = GetBitLength(m_byBlockMode[nBlock], m_nBlockLength[nBlock], nVerGroup)
					+ GetBitLength(m_byBlockMode[nBlock + 1], m_nBlockLength[nBlock + 1], nVerGroup);

		ncDstBits = GetBitLength(QR_MODE_8BIT, m_nBlockLength[nBlock] + m_nBlockLength[nBlock + 1], nVerGroup);

		// If there is a 8-bit byte block mode before, subtract the duplicate indicator minute
		if (nBlock >= 1 && m_byBlockMode[nBlock - 1] == QR_MODE_8BIT) {
			ncDstBits -= (4 + nIndicatorLen8Bit[nVerGroup]);
		}

		// If there is a block behind the 8-bit byte mode, subtract the duplicate indicator minute
		if (nBlock < m_ncDataBlock - 2 && m_byBlockMode[nBlock + 2] == QR_MODE_8BIT) {
			ncDstBits -= (4 + nIndicatorLen8Bit[nVerGroup]);
		}

		if (ncSrcBits > ncDstBits) {
			if (nBlock >= 1 && m_byBlockMode[nBlock - 1] == QR_MODE_8BIT) {
				// 8-bit byte mode coupling block in front of the block to join
				m_nBlockLength[nBlock - 1] += m_nBlockLength[nBlock];

				// The subsequent shift
				for (i = nBlock; i < m_ncDataBlock - 1; i++) {
					m_byBlockMode[i] = m_byBlockMode[i + 1];
					m_nBlockLength[i] = m_nBlockLength[i + 1];
				}

				m_ncDataBlock--;
				nBlock--;
			}

			if (nBlock < m_ncDataBlock - 2 && m_byBlockMode[nBlock + 2] == QR_MODE_8BIT) {
				// 8-bit byte mode coupling block at the back of the block to join
				m_nBlockLength[nBlock + 1] += m_nBlockLength[nBlock + 2];

				// The subsequent shift
				for (i = nBlock + 2; i < m_ncDataBlock - 1; i++) {
					m_byBlockMode[i] = m_byBlockMode[i + 1];
					m_nBlockLength[i] = m_nBlockLength[i + 1];
				}

				m_ncDataBlock--;
			}

			m_byBlockMode[nBlock] = QR_MODE_8BIT;
			m_nBlockLength[nBlock] += m_nBlockLength[nBlock + 1];

			// The subsequent shift
			for (i = nBlock + 1; i < m_ncDataBlock - 1; i++) {
				m_byBlockMode[i] = m_byBlockMode[i + 1];
				m_nBlockLength[i] = m_nBlockLength[i + 1];
			}

			m_ncDataBlock--;

			// Re-examination in front of the block bound
			if (nBlock >= 1) {
				nBlock--;
			}

			continue;
		}

		nBlock++;// Investigate the next block

	}

	// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
	// Mosquito bit array
	int ncComplete = 0;	// Data pre-processing counter

	uint16_t wBinCode;

	m_ncDataCodeWordBit = 0;// Bit counter processing unit

	memset(m_byDataCodeWord, 0, sizeof(m_byDataCodeWord));

	for (i = 0; i < m_ncDataBlock && m_ncDataCodeWordBit != -1; i++) {
		if (m_byBlockMode[i] == QR_MODE_NUMERAL) {
			// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
			// Numeric mode
			// Indicator (0001b)
			m_ncDataCodeWordBit = SetBitStream(m_ncDataCodeWordBit, 1, 4);

			// Set number of characters
			m_ncDataCodeWordBit = SetBitStream(m_ncDataCodeWordBit, (uint16_t)m_nBlockLength[i], nIndicatorLenNumeral[nVerGroup]);

			// Save the bit string
			for (j = 0; j < m_nBlockLength[i]; j += 3) {
				if (j < m_nBlockLength[i] - 2) {
					wBinCode = (uint16_t)(((lpsSource[ncComplete + j] - '0') * 100) +
									((lpsSource[ncComplete + j + 1] - '0') * 10) +
									(lpsSource[ncComplete + j + 2] - '0'));

					m_ncDataCodeWordBit = SetBitStream(m_ncDataCodeWordBit, wBinCode, 10);
				} else
				if (j == m_nBlockLength[i] - 2) {

					// 2 bytes fraction
					wBinCode = (uint16_t)(((lpsSource[ncComplete + j] - '0') * 10) +
									(lpsSource[ncComplete + j + 1] - '0'));

					m_ncDataCodeWordBit = SetBitStream(m_ncDataCodeWordBit, wBinCode, 7);
				} else
				if (j == m_nBlockLength[i] - 1) {

					// A fraction of bytes
					wBinCode = (uint16_t)(lpsSource[ncComplete + j] - '0');

					m_ncDataCodeWordBit = SetBitStream(m_ncDataCodeWordBit, wBinCode, 4);
				}
			}

			ncComplete += m_nBlockLength[i];
		}

		else
		if (m_byBlockMode[i] == QR_MODE_ALPHABET) {
			// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
			// Alphanumeric mode
			// Mode indicator (0010b)
			m_ncDataCodeWordBit = SetBitStream(m_ncDataCodeWordBit, 2, 4);

			// Set number of characters
			m_ncDataCodeWordBit = SetBitStream(m_ncDataCodeWordBit, (uint16_t)m_nBlockLength[i], nIndicatorLenAlphabet[nVerGroup]);

			// Save the bit string
			for (j = 0; j < m_nBlockLength[i]; j += 2) {
				if (j < m_nBlockLength[i] - 1) {
					wBinCode = (uint16_t)((AlphabetToBinary(lpsSource[ncComplete + j]) * 45) +
									AlphabetToBinary(lpsSource[ncComplete + j + 1]));

					m_ncDataCodeWordBit = SetBitStream(m_ncDataCodeWordBit, wBinCode, 11);
				} else {
					// A fraction of bytes
					wBinCode = (uint16_t)AlphabetToBinary(lpsSource[ncComplete + j]);

					m_ncDataCodeWordBit = SetBitStream(m_ncDataCodeWordBit, wBinCode, 6);
				}
			}

			ncComplete += m_nBlockLength[i];
		}

		else { // (m_byBlockMode[i] == QR_MODE_8BIT)
			// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
			// 8-bit byte mode

			// Mode indicator (0100b)
			m_ncDataCodeWordBit = SetBitStream(m_ncDataCodeWordBit, 4, 4);

			// Set number of characters
			m_ncDataCodeWordBit = SetBitStream(m_ncDataCodeWordBit, (uint16_t)m_nBlockLength[i], nIndicatorLen8Bit[nVerGroup]);

			// Save the bit string
			for (j = 0; j < m_nBlockLength[i]; j++) {
				m_ncDataCodeWordBit = SetBitStream(m_ncDataCodeWordBit, (uint16_t)lpsSource[ncComplete + j], 8);
			}

			ncComplete += m_nBlockLength[i];
		}
	}

	return (m_ncDataCodeWordBit != -1);
}

// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
// APPLICATIONS: To get the bit length
// Args: data mode type, data length, group version (model number)
// Returns: data bit length

int GetEncodeVersion(int nVersion, const char* lpsSource, int ncLength)
{
	int nVerGroup = nVersion >= 27 ? QR_VERSION_L : (nVersion >= 10 ? QR_VERSION_M : QR_VERSION_S);
	int i, j;

	for (i = nVerGroup; i <= QR_VERSION_L; i++) {
		if (EncodeSourceData(lpsSource, ncLength, i)) {
			if (i == QR_VERSION_S) {
				for (j = 1; j <= 9; j++) {
					if ((m_ncDataCodeWordBit + 7) / 8 <= QR_VersonInfo[j].ncDataCodeWord[m_nLevel]) {
						return j;
					}
				}
			}
#if QR_MAX_VERSION >= QR_VERSION_M
			else
			if (i == QR_VERSION_M) {
				for (j = 10; j <= 26; j++) {
					if ((m_ncDataCodeWordBit + 7) / 8 <= QR_VersonInfo[j].ncDataCodeWord[m_nLevel]) {
						return j;
					}
				}
			}
#endif
#if QR_MAX_VERSION >= QR_VERSION_L
			else
			if (i == QR_VERSION_L) {
				for (j = 27; j <= 40; j++) {
					if ((m_ncDataCodeWordBit + 7) / 8 <= QR_VersonInfo[j].ncDataCodeWord[m_nLevel]) {
						return j;
					}
				}
			}
#endif
		}
	}

	return 0;
}

void GetRSCodeWord(uint8_t* lpbyRSWork, int ncDataCodeWord, int ncRSCodeWord)
{
	int i, j;

	for (i = 0; i < ncDataCodeWord ; i++) {
		if (lpbyRSWork[0] != 0) {
			uint8_t nExpFirst = byIntToExp[lpbyRSWork[0]]; // Multiplier coefficient is calculated from the first term

			for (j = 0; j < ncRSCodeWord; j++) {

				// Add (% 255 ^ 255 = 1) the first term multiplier to multiplier sections
				uint8_t nExpElement = (uint8_t)(((int)(byRSExp[ncRSCodeWord][j] + nExpFirst)) % 255);

				// Surplus calculated by the exclusive
				lpbyRSWork[j] = (uint8_t)(lpbyRSWork[j + 1] ^ byExpToInt[nExpElement]);
			}

			// Shift the remaining digits
			for (j = ncRSCodeWord; j < ncDataCodeWord + ncRSCodeWord - 1; j++) {
				lpbyRSWork[j] = lpbyRSWork[j + 1];
			}
		} else {
			// Shift the remaining digits
			for (j = 0; j < ncDataCodeWord + ncRSCodeWord - 1; j++) {
				lpbyRSWork[j] = lpbyRSWork[j + 1];
			}
		}
	}
}

void SetFinderPattern(int x, int y)
{
	static const uint8_t byPattern[] = {	0x7f,	// 1111111b
											0x41,	// 1000001b
											0x5d,	// 1011101b
											0x5d,	// 1011101b
											0x5d,	// 1011101b
											0x41,	// 1000001b
											0x7f};	// 1111111b
	int i, j;

	for (i = 0; i < 7; i++) {
		for (j = 0; j < 7; j++) {
			m_byModuleData[x + j][y + i] = (byPattern[i] & (1 << (6 - j))) ? '\x30' : '\x20';
		}
	}
}

void SetVersionPattern(void)
{
	int i, j;

	if (m_nVersion <= 6) {
		return;
	}

	int nVerData = m_nVersion << 12;

	// Calculated bit remainder

	for (i = 0; i < 6; i++) {
		if (nVerData & (1 << (17 - i))) {
			nVerData ^= (0x1f25 << (5 - i));
		}
	}

	nVerData += m_nVersion << 12;

	for (i = 0; i < 6; i++) {
		for (j = 0; j < 3; j++) {
			m_byModuleData[m_nSymbleSize - 11 + j][i] = m_byModuleData[i][m_nSymbleSize - 11 + j] =
			(nVerData & (1 << (i * 3 + j))) ? '\x30' : '\x20';
		}
	}
}

void SetAlignmentPattern(int x, int y)
{
	static const uint8_t byPattern[] = {	0x1f,	// 11111b
											0x11,	// 10001b
											0x15,	// 10101b
											0x11,	// 10001b
											0x1f};	// 11111b
	int i, j;

	if (m_byModuleData[x][y] & 0x20) {
		return; 		// Excluded due to overlap with the functional module
	}

	x -= 2; y -= 2; 	// Convert the coordinates to the upper left corner

	for (i = 0; i < 5; i++) {
		for (j = 0; j < 5; j++) {
			m_byModuleData[x + j][y + i] = (byPattern[i] & (1 << (4 - j))) ? '\x30' : '\x20';
		}
	}
}

void SetFunctionModule(void)
{
	int i, j;

	// Position detection pattern
	SetFinderPattern(0, 0);
	SetFinderPattern(m_nSymbleSize - 7, 0);
	SetFinderPattern(0, m_nSymbleSize - 7);

	// Separator pattern position detection
	for (i = 0; i < 8; i++) {
		m_byModuleData[i][7] = m_byModuleData[7][i] = '\x20';
		m_byModuleData[m_nSymbleSize - 8][i] = m_byModuleData[m_nSymbleSize - 8 + i][7] = '\x20';
		m_byModuleData[i][m_nSymbleSize - 8] = m_byModuleData[7][m_nSymbleSize - 8 + i] = '\x20';
	}

	// Registration as part of a functional module position description format information
	for (i = 0; i < 9; i++) {
		m_byModuleData[i][8] = m_byModuleData[8][i] = '\x20';
	}

	for (i = 0; i < 8; i++) {
		m_byModuleData[m_nSymbleSize - 8 + i][8] = m_byModuleData[8][m_nSymbleSize - 8 + i] = '\x20';
	}

	// Version information pattern
	SetVersionPattern();

	// Pattern alignment
	for (i = 0; i < QR_VersonInfo[m_nVersion].ncAlignPoint; i++) {
		SetAlignmentPattern(QR_VersonInfo[m_nVersion].nAlignPoint[i], 6);
		SetAlignmentPattern(6, QR_VersonInfo[m_nVersion].nAlignPoint[i]);

		for (j = 0; j < QR_VersonInfo[m_nVersion].ncAlignPoint; j++) {
			SetAlignmentPattern(QR_VersonInfo[m_nVersion].nAlignPoint[i], QR_VersonInfo[m_nVersion].nAlignPoint[j]);
		}
	}

	// Timing pattern
	for (i = 8; i <= m_nSymbleSize - 9; i++) {
		m_byModuleData[i][6] = (i % 2) == 0 ? '\x30' : '\x20';
		m_byModuleData[6][i] = (i % 2) == 0 ? '\x30' : '\x20';
	}
}

void SetCodeWordPattern(void)
{
	int x = m_nSymbleSize;
	int y = m_nSymbleSize - 1;

	int nCoef_x = 1; 	// placement orientation axis x
	int nCoef_y = 1; 	// placement orientation axis y

	int i, j;

	for (i = 0; i < m_ncAllCodeWord; i++) {
		for (j = 0; j < 8; j++) {
			do {
				x += nCoef_x;
				nCoef_x *= -1;

				if (nCoef_x < 0) {
					y += nCoef_y;

					if (y < 0 || y == m_nSymbleSize) {
						y = (y < 0) ? 0 : m_nSymbleSize - 1;
						nCoef_y *= -1;

						x -= 2;

						if (x == 6) { // Timing pattern
							x--;
						}
					}
				}
			} while (m_byModuleData[x][y] & 0x20); // Exclude a functional module

			m_byModuleData[x][y] = (m_byAllCodeWord[i] & (1 << (7 - j))) ? '\x02' : '\x00';

		}
	}
}

void SetMaskingPattern(int nPatternNo)
{
	int i, j;

	for (i = 0; i < m_nSymbleSize; i++) {
		for (j = 0; j < m_nSymbleSize; j++) {
			if (! (m_byModuleData[j][i] & 0x20)) { // Exclude a functional module
				int bMask;

				switch (nPatternNo) {
					case 0:
						bMask = ((i + j) % 2 == 0);
						break;
					case 1:
						bMask = (i % 2 == 0);
						break;
					case 2:
						bMask = (j % 3 == 0);
						break;
					case 3:
						bMask = ((i + j) % 3 == 0);
						break;
					case 4:
						bMask = (((i / 2) + (j / 3)) % 2 == 0);
						break;
					case 5:
						bMask = (((i * j) % 2) + ((i * j) % 3) == 0);
						break;
					case 6:
						bMask = ((((i * j) % 2) + ((i * j) % 3)) % 2 == 0);
						break;
					default: // case 7:
						bMask = ((((i * j) % 3) + ((i + j) % 2)) % 2 == 0);
						break;
				}

				m_byModuleData[j][i] = (uint8_t)((m_byModuleData[j][i] & 0xfe) | (((m_byModuleData[j][i] & 0x02) > 1) ^ bMask));
			}
		}
	}
}

void SetFormatInfoPattern(int nPatternNo)
{
	int nFormatInfo;
	int i;
	switch (m_nLevel) {
		case QR_LEVEL_L:
			nFormatInfo = 0x08; // 01nnnb
			break;
		case QR_LEVEL_M:
			nFormatInfo = 0x00; // 00nnnb
			break;
		case QR_LEVEL_Q:
			nFormatInfo = 0x18; // 11nnnb
			break;
		default: // case QR_LEVEL_H:
			nFormatInfo = 0x10; // 10nnnb
			break;
	}
	nFormatInfo += nPatternNo;
	int nFormatData = nFormatInfo << 10;
	// Calculated bit remainder
	for (i = 0; i < 5; i++) {
		if (nFormatData & (1 << (14 - i))) {
			nFormatData ^= (0x0537 << (4 - i)); // 10100110111b
		}
	}
	nFormatData += nFormatInfo << 10;
	// Masking
	nFormatData ^= 0x5412; // 101010000010010b
	// Position detection patterns located around the upper left
	for (i = 0; i <= 5; i++) {
		m_byModuleData[8][i] = (nFormatData & (1 << i)) ? '\x30' : '\x20';
	}
	m_byModuleData[8][7] = (nFormatData & (1 << 6)) ? '\x30' : '\x20';
	m_byModuleData[8][8] = (nFormatData & (1 << 7)) ? '\x30' : '\x20';
	m_byModuleData[7][8] = (nFormatData & (1 << 8)) ? '\x30' : '\x20';
	for (i = 9; i <= 14; i++) {
		m_byModuleData[14 - i][8] = (nFormatData & (1 << i)) ? '\x30' : '\x20';
	}
	// Position detection patterns located under the upper right corner
	for (i = 0; i <= 7; i++) {
		m_byModuleData[m_nSymbleSize - 1 - i][8] = (nFormatData & (1 << i)) ? '\x30' : '\x20';
	}
	// Right lower left position detection patterns located
	m_byModuleData[8][m_nSymbleSize - 8] = '\x30'; 	// Module fixed dark
	for (i = 8; i <= 14; i++) {
		m_byModuleData[8][m_nSymbleSize - 15 + i] = (nFormatData & (1 << i)) ? '\x30' : '\x20';
	}
}

int CountPenalty(void)
{
	int nPenalty = 0;
	int i, j, k;

	// Column of the same color adjacent module
	for (i = 0; i < m_nSymbleSize; i++) {
		for (j = 0; j < m_nSymbleSize - 4; j++) {
			int nCount = 1;

			for (k = j + 1; k < m_nSymbleSize; k++) {
				if (((m_byModuleData[i][j] & 0x11) == 0) == ((m_byModuleData[i][k] & 0x11) == 0)) {
					nCount++;
				} else {
					break;
				}
			}

			if (nCount >= 5) {
				nPenalty += 3 + (nCount - 5);
			}

			j = k - 1;
		}
	}

	// Adjacent module line of the same color
	for (i = 0; i < m_nSymbleSize; i++) {
		for (j = 0; j < m_nSymbleSize - 4; j++) {
			int nCount = 1;

			for (k = j + 1; k < m_nSymbleSize; k++) {
				if (((m_byModuleData[j][i] & 0x11) == 0) == ((m_byModuleData[k][i] & 0x11) == 0)) {
					nCount++;
				} else {
					break;
				}
			}

			if (nCount >= 5) {
				nPenalty += 3 + (nCount - 5);
			}

			j = k - 1;
		}
	}

	// Modules of the same color block (2 ~ 2)
	for (i = 0; i < m_nSymbleSize - 1; i++) {
		for (j = 0; j < m_nSymbleSize - 1; j++) {
			if ((((m_byModuleData[i][j] & 0x11) == 0) == ((m_byModuleData[i + 1][j]		& 0x11) == 0)) &&
				(((m_byModuleData[i][j] & 0x11) == 0) == ((m_byModuleData[i]	[j + 1] & 0x11) == 0)) &&
				(((m_byModuleData[i][j] & 0x11) == 0) == ((m_byModuleData[i + 1][j + 1] & 0x11) == 0))) {
				nPenalty += 3;
			}
		}
	}

	// Pattern (dark dark: light: dark: light) ratio 1:1:3:1:1 in the same column
	for (i = 0; i < m_nSymbleSize; i++) {
		for (j = 0; j < m_nSymbleSize - 6; j++) {
			if (((j == 0) ||				 (! (m_byModuleData[i][j - 1] & 0x11))) &&
											 (   m_byModuleData[i][j    ] & 0x11) &&
											 (! (m_byModuleData[i][j + 1] & 0x11)) &&
											 (   m_byModuleData[i][j + 2] & 0x11) &&
											 (   m_byModuleData[i][j + 3] & 0x11) &&
											 (   m_byModuleData[i][j + 4] & 0x11) &&
											 (! (m_byModuleData[i][j + 5] & 0x11)) &&
											 (   m_byModuleData[i][j + 6] & 0x11) &&
				((j == m_nSymbleSize - 7) || (! (m_byModuleData[i][j + 7] & 0x11)))) {

				// Clear pattern of four or more before or after
				if (((j < 2 || ! (m_byModuleData[i][j - 2] & 0x11)) &&
					 (j < 3 || ! (m_byModuleData[i][j - 3] & 0x11)) &&
					 (j < 4 || ! (m_byModuleData[i][j - 4] & 0x11))) ||
					((j >= m_nSymbleSize - 8 || ! (m_byModuleData[i][j + 8] & 0x11)) &&
					 (j >= m_nSymbleSize - 9 || ! (m_byModuleData[i][j + 9] & 0x11)) &&
					 (j >= m_nSymbleSize - 10 || ! (m_byModuleData[i][j + 10] & 0x11)))) {
					nPenalty += 40;
				}
			}
		}
	}

	// Pattern (dark dark: light: dark: light) in the same line ratio 1:1:3:1:1
	for (i = 0; i < m_nSymbleSize; i++) {
		for (j = 0; j < m_nSymbleSize - 6; j++) {
			if (((j == 0) ||				 (! (m_byModuleData[j - 1][i] & 0x11))) &&
											 (   m_byModuleData[j   ] [i] & 0x11) &&
											 (! (m_byModuleData[j + 1][i] & 0x11)) &&
											 (   m_byModuleData[j + 2][i] & 0x11) &&
											 (   m_byModuleData[j + 3][i] & 0x11) &&
											 (   m_byModuleData[j + 4][i] & 0x11) &&
											 (! (m_byModuleData[j + 5][i] & 0x11)) &&
											 (   m_byModuleData[j + 6][i] & 0x11) &&
				((j == m_nSymbleSize - 7) || (! (m_byModuleData[j + 7][i] & 0x11)))) {

				// Clear pattern of four or more before or after
				if (((j < 2 || ! (m_byModuleData[j - 2][i] & 0x11)) &&
					 (j < 3 || ! (m_byModuleData[j - 3][i] & 0x11)) &&
					 (j < 4 || ! (m_byModuleData[j - 4][i] & 0x11))) ||
					((j >= m_nSymbleSize - 8 || ! (m_byModuleData[j + 8][i] & 0x11)) &&
					 (j >= m_nSymbleSize - 9 || ! (m_byModuleData[j + 9][i] & 0x11)) &&
					 (j >= m_nSymbleSize - 10 || ! (m_byModuleData[j + 10][i] & 0x11)))) {
					nPenalty += 40;
				}
			}
		}
	}

	// The proportion of modules for the entire dark
	int nCount = 0;

	for (i = 0; i < m_nSymbleSize; i++) {
		for (j = 0; j < m_nSymbleSize; j++) {
			if (! (m_byModuleData[i][j] & 0x11)) {
				nCount++;
			}
		}
	}

	nPenalty += (abs(50 - ((nCount * 100) / (m_nSymbleSize * m_nSymbleSize))) / 5) * 10;

	return nPenalty;
}

void FormatModule(void)
{
	int i, j;

	memset(m_byModuleData, 0, sizeof(m_byModuleData));

	// Function module placement
	SetFunctionModule();

	// Data placement
	SetCodeWordPattern();

	if (m_nMaskingNo == -1) {

		// Select the best pattern masking
		m_nMaskingNo = 0;

		SetMaskingPattern(m_nMaskingNo); 		// Masking
		SetFormatInfoPattern(m_nMaskingNo); 	// Placement pattern format information

		int nMinPenalty = CountPenalty();

		for (i = 1; i <= 7; i++) {
			SetMaskingPattern(i); 			// Masking
			SetFormatInfoPattern(i); 		// Placement pattern format information

			int nPenalty = CountPenalty();

			if (nPenalty < nMinPenalty) {
				nMinPenalty = nPenalty;
				m_nMaskingNo = i;
			}
		}
	}

	SetMaskingPattern(m_nMaskingNo); 	// Masking
	SetFormatInfoPattern(m_nMaskingNo); // Placement pattern format information

	// The module pattern converted to a Boolean value

	for (i = 0; i < m_nSymbleSize; i++) {
		for (j = 0; j < m_nSymbleSize; j++) {
			m_byModuleData[i][j] = (uint8_t)((m_byModuleData[i][j] & 0x11) != 0);
		}
	}
}

void putBitToPos(uint32_t pos, int bw, uint8_t *bits)
{
	if (bw == 0) return;
	uint32_t tmp;
	uint32_t bitpos[8] = {128, 64, 32, 16, 8, 4, 2, 1};
	if (pos % 8 == 0) {
		tmp = (pos / 8) - 1;
		bits[tmp] = bits[tmp] ^ bitpos[7];
	} else {
		tmp = pos / 8;
		bits[tmp] = bits[tmp] ^ bitpos[pos % 8 - 1];
	}
}

int qr_encode(int level, int version, const char *source, size_t source_len, uint8_t *result)
{
	int i, j;
	const bool auto_extent = 1;
	m_nLevel = level;
	m_nMaskingNo = -1;

	memset(result, 0, QR_MAX_BITDATA);
	// If the data length is not specified, acquired by lstrlen
	size_t ncLength = source_len > 0 ? source_len : strlen(source);

	if (ncLength == 0) {
		return -1; // No data
	}

	// Check version (model number)

	nEncodeVersion = GetEncodeVersion(version, source, ncLength);

	if (nEncodeVersion == 0) {
		return -1; // Over-capacity
	}
	if (version == 0) {
		// Auto Part
		m_nVersion = nEncodeVersion;
	} else {
		if (nEncodeVersion <= version) {
			m_nVersion = version;
		} else {
			if (auto_extent) {
				m_nVersion = nEncodeVersion; // Automatic extended version (model number)
			} else {
				return -1; // Over-capacity
			}
		}
	}

	// Terminator addition code "0000"
	int ncDataCodeWord = QR_VersonInfo[m_nVersion].ncDataCodeWord[level];

	int ncTerminater = (ncDataCodeWord * 8) - m_ncDataCodeWordBit;
	if (ncTerminater < 4) {
		ncTerminater = 4;
	}

	if (ncTerminater > 0) {
		m_ncDataCodeWordBit = SetBitStream(m_ncDataCodeWordBit, 0, ncTerminater);
	}

	// Additional padding code "11101100, 00010001"
	uint8_t byPaddingCode = 0xec;

	for (i = (m_ncDataCodeWordBit + 7) / 8; i < ncDataCodeWord; i++) {
		m_byDataCodeWord[i] = byPaddingCode;

		byPaddingCode = (uint8_t)(byPaddingCode == 0xec ? 0x11 : 0xec);
	}

	// Calculated the total clear area code word
	m_ncAllCodeWord = QR_VersonInfo[m_nVersion].ncAllCodeWord;

	memset(m_byAllCodeWord, 0, sizeof(m_byAllCodeWord));

	int nDataCwIndex = 0;	// Position data processing code word

	// Division number data block
	int ncBlock1 = QR_VersonInfo[m_nVersion].RS_BlockInfo1[level].ncRSBlock;

	int ncBlock2 = QR_VersonInfo[m_nVersion].RS_BlockInfo2[level].ncRSBlock;

	int ncBlockSum = ncBlock1 + ncBlock2;

	int nBlockNo = 0; // Block number in the process

	// The number of data code words by block
	int ncDataCw1 = QR_VersonInfo[m_nVersion].RS_BlockInfo1[level].ncDataCodeWord;

	int ncDataCw2 = QR_VersonInfo[m_nVersion].RS_BlockInfo2[level].ncDataCodeWord;

	// Code word interleaving data placement
	for (i = 0; i < ncBlock1; i++) {
		for (j = 0; j < ncDataCw1; j++) {
			m_byAllCodeWord[(ncBlockSum * j) + nBlockNo] = m_byDataCodeWord[nDataCwIndex++];
		}

		nBlockNo++;
	}

	for (i = 0; i < ncBlock2; i++) {
		for (j = 0; j < ncDataCw2; j++) {
			if (j < ncDataCw1) {
				m_byAllCodeWord[(ncBlockSum * j) + nBlockNo] = m_byDataCodeWord[nDataCwIndex++];
			} else {
				// 2 minute fraction block placement event
				m_byAllCodeWord[(ncBlockSum * ncDataCw1) + i] = m_byDataCodeWord[nDataCwIndex++];
			}
		}
		nBlockNo++;
	}

	// RS code words by block number (currently the same number)
	int ncRSCw1 = QR_VersonInfo[m_nVersion].RS_BlockInfo1[level].ncAllCodeWord - ncDataCw1;
	int ncRSCw2 = QR_VersonInfo[m_nVersion].RS_BlockInfo2[level].ncAllCodeWord - ncDataCw2;

	// RS code word is calculated

	nDataCwIndex = 0;
	nBlockNo = 0;

	for (i = 0; i < ncBlock1; i++) {
		memset(m_byRSWork, 0, sizeof(m_byRSWork));
		memmove(m_byRSWork, m_byDataCodeWord + nDataCwIndex, ncDataCw1);
		GetRSCodeWord(m_byRSWork, ncDataCw1, ncRSCw1);
		// RS code word placement
		for (j = 0; j < ncRSCw1; j++) {
			m_byAllCodeWord[ncDataCodeWord + (ncBlockSum * j) + nBlockNo] = m_byRSWork[j];
		}
		nDataCwIndex += ncDataCw1;
		nBlockNo++;
	}

	for (i = 0; i < ncBlock2; i++) {
		memset(m_byRSWork, 0, sizeof(m_byRSWork));
		memmove(m_byRSWork, m_byDataCodeWord + nDataCwIndex, ncDataCw2);
		GetRSCodeWord(m_byRSWork, ncDataCw2, ncRSCw2);
		// RS code word placement
		for (j = 0; j < ncRSCw2; j++) {
			m_byAllCodeWord[ncDataCodeWord + (ncBlockSum * j) + nBlockNo] = m_byRSWork[j];
		}
		nDataCwIndex += ncDataCw2;
		nBlockNo++;
	}

	m_nSymbleSize = m_nVersion * 4 + 17;

	// Module placement
	FormatModule();

	for (i = 0; i < m_nSymbleSize; i++) {
		for (j = 0; j < m_nSymbleSize; j++) {
			if (!m_byModuleData[i][j]) {
				putBitToPos((j * m_nSymbleSize) + i + 1, 0, result);
			} else {
				putBitToPos((j * m_nSymbleSize) + i + 1, 1, result);
			}
		}
	}
	return m_nSymbleSize;
}
