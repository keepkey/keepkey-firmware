extern "C" {
#include "keepkey/firmware/erc7730_program.h"
}

#include <gtest/gtest.h>

#include <vector>

namespace {

void append32(std::vector<uint8_t>& out, uint32_t value) {
  out.push_back((uint8_t)(value >> 24));
  out.push_back((uint8_t)(value >> 16));
  out.push_back((uint8_t)(value >> 8));
  out.push_back((uint8_t)value);
}

std::vector<uint8_t> indexedProgram() {
  std::vector<uint8_t> p(ERC7730_PROGRAM_HEADER_SIZE, 0);
  p.back() = 3;
  p.push_back(1);
  append32(p, 3);
  p.insert(p.end(), {1, 2, 3});
  p.push_back(7);
  append32(p, 2);
  p.insert(p.end(), {4, 5});
  p.push_back(9);
  append32(p, 1);
  p.push_back(6);
  return p;
}

}  // namespace

TEST(Erc7730ProgramIndex, IndexesArbitraryChunkBoundaries) {
  const auto program = indexedProgram();
  for (size_t chunk : {1u, 4u, 5u, 17u, 1024u}) {
    Erc7730ProgramIndex index;
    erc7730_program_index_begin(&index, (uint32_t)program.size());
    for (size_t offset = 0; offset < program.size();) {
      const size_t length = std::min(chunk, (size_t)(program.size() - offset));
      ASSERT_TRUE(erc7730_program_index_feed(&index, (uint32_t)offset,
                                             program.data() + offset, length));
      offset += length;
    }
    ASSERT_TRUE(erc7730_program_index_complete(&index));
    Erc7730ProgramSection section;
    ASSERT_TRUE(erc7730_program_index_section(&index, 1, &section));
    EXPECT_EQ(section.offset, ERC7730_PROGRAM_HEADER_SIZE + 5u);
    EXPECT_EQ(section.length, 3u);
    ASSERT_TRUE(erc7730_program_index_section(&index, 7, &section));
    EXPECT_EQ(section.length, 2u);
    EXPECT_FALSE(erc7730_program_index_section(&index, 2, &section));
  }
}

TEST(Erc7730ProgramIndex, RejectsSequenceTruncationAndInvalidSections) {
  auto program = indexedProgram();
  Erc7730ProgramIndex index;
  erc7730_program_index_begin(&index, (uint32_t)program.size());
  EXPECT_FALSE(erc7730_program_index_feed(&index, 1, program.data(), 1));

  erc7730_program_index_begin(&index, (uint32_t)program.size());
  program[ERC7730_PROGRAM_HEADER_SIZE + 8] = 1;  // duplicate/out of order
  EXPECT_FALSE(
      erc7730_program_index_feed(&index, 0, program.data(), program.size()));

  program = indexedProgram();
  erc7730_program_index_begin(&index, (uint32_t)program.size() - 1u);
  EXPECT_FALSE(erc7730_program_index_feed(&index, 0, program.data(),
                                          program.size() - 1u));
  EXPECT_FALSE(erc7730_program_index_complete(&index));
}
