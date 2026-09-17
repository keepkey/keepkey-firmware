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

TEST(Erc7730ProgramAbi, LoadsValidatedNodesAcrossChunks) {
  const std::vector<uint8_t> section = {
      0, 3, ERC7730_ABI_TUPLE,   0, 0, 0, 1, 0, 2,
      0, 0, ERC7730_ABI_ADDRESS, 0, 0, 0, 0, 0, 0,
      0, 0, ERC7730_ABI_UINT,    1, 0, 0, 0, 0, 0,
      0, 0,
  };
  for (size_t chunk : {1u, 7u, 29u}) {
    Erc7730ProgramAbi abi;
    erc7730_program_abi_begin(&abi, (uint32_t)section.size());
    for (size_t offset = 0; offset < section.size();) {
      const size_t length = std::min(chunk, section.size() - offset);
      ASSERT_TRUE(erc7730_program_abi_feed(&abi, (uint32_t)offset,
                                           section.data() + offset, length));
      offset += length;
    }
    Erc7730AbiProgram program;
    ASSERT_TRUE(erc7730_program_abi_complete(&abi, &program));
    EXPECT_EQ(program.node_count, 3u);
    EXPECT_EQ(program.nodes[2].kind, ERC7730_ABI_UINT);
    EXPECT_EQ(program.nodes[2].size, 256u);
  }
}

TEST(Erc7730ProgramAbi, RejectsMalformedGraphAndLength) {
  const std::vector<uint8_t> section = {
      0, 1, ERC7730_ABI_TUPLE, 0, 0, 0, 1, 0, 1, 0, 0,
  };
  Erc7730ProgramAbi abi;
  erc7730_program_abi_begin(&abi, (uint32_t)section.size());
  EXPECT_FALSE(
      erc7730_program_abi_feed(&abi, 0, section.data(), section.size()));

  erc7730_program_abi_begin(&abi, 10);
  EXPECT_TRUE(abi.failed);
}

TEST(Erc7730ProgramLoader, RetainsAbiDuringSingleArbitraryChunkReplay) {
  const std::vector<uint8_t> abi = {
      0, 2, ERC7730_ABI_TUPLE,   0, 0, 0, 1, 0, 1,
      0, 0, ERC7730_ABI_ADDRESS, 0, 0, 0, 0, 0, 0,
      0, 0,
  };
  std::vector<uint8_t> program(ERC7730_PROGRAM_HEADER_SIZE, 0);
  program.back() = 2;
  program.push_back(ERC7730_PROGRAM_SECTION_ABI);
  append32(program, abi.size());
  program.insert(program.end(), abi.begin(), abi.end());
  program.push_back(7);
  append32(program, 3);
  program.insert(program.end(), {1, 2, 3});

  for (size_t chunk : {1u, 5u, 17u, 1024u}) {
    Erc7730ProgramLoader loader;
    erc7730_program_loader_begin(&loader, program.size());
    for (size_t offset = 0; offset < program.size();) {
      const size_t length = std::min(chunk, program.size() - offset);
      ASSERT_TRUE(erc7730_program_loader_feed(&loader, offset,
                                              program.data() + offset, length));
      offset += length;
    }
    Erc7730AbiProgram loaded;
    ASSERT_TRUE(erc7730_program_loader_complete(&loader, &loaded));
    ASSERT_EQ(loaded.node_count, 2u);
    EXPECT_EQ(loaded.nodes[1].kind, ERC7730_ABI_ADDRESS);
  }
}

TEST(Erc7730ProgramLoader, RefusesMissingOrMalformedAbiSection) {
  auto missing = indexedProgram();
  Erc7730ProgramLoader loader;
  erc7730_program_loader_begin(&loader, missing.size());
  EXPECT_TRUE(
      erc7730_program_loader_feed(&loader, 0, missing.data(), missing.size()));
  Erc7730AbiProgram loaded;
  EXPECT_FALSE(erc7730_program_loader_complete(&loader, &loaded));

  auto malformed = indexedProgram();
  malformed[ERC7730_PROGRAM_HEADER_SIZE] = ERC7730_PROGRAM_SECTION_ABI;
  erc7730_program_loader_begin(&loader, malformed.size());
  EXPECT_FALSE(erc7730_program_loader_feed(&loader, 0, malformed.data(),
                                           malformed.size()));
}

TEST(Erc7730ProgramPath, SelectsStructuredContainerAndSlicePaths) {
  const std::vector<uint8_t> section = {
      0, 3, 1, 2,    0xff, 0xff, 1, 0xff, 0xff, 0xff, 0xff, 2, 2, 0, 0,
      4, 1, 1, 0xff, 0xff, 3,    3, 0xff, 0xff, 0xff, 0xfe, 0, 0, 0, 5,
  };
  for (uint16_t target = 0; target < 3; target++) {
    for (size_t chunk : {1u, 5u, 64u}) {
      Erc7730ProgramPath loader;
      erc7730_program_path_begin(&loader, (uint32_t)section.size(), target);
      for (size_t offset = 0; offset < section.size();) {
        const size_t length = std::min(chunk, section.size() - offset);
        ASSERT_TRUE(erc7730_program_path_feed(&loader, (uint32_t)offset,
                                              section.data() + offset, length));
        offset += length;
      }
      Erc7730Path path;
      ASSERT_TRUE(erc7730_program_path_complete(&loader, &path));
      if (target == 0) {
        EXPECT_EQ(path.source, 1);
        EXPECT_EQ(path.step_count, 2);
        EXPECT_EQ(path.steps[0].first, -1);
        EXPECT_EQ(path.steps[1].opcode, 2);
      } else if (target == 1) {
        EXPECT_EQ(path.source, 2);
        EXPECT_EQ(path.source_index, 4);
      } else {
        EXPECT_EQ(path.steps[0].opcode, 3);
        EXPECT_EQ(path.steps[0].flags, 3);
        EXPECT_EQ(path.steps[0].first, -2);
        EXPECT_EQ(path.steps[0].second, 5);
      }
    }
  }
}

TEST(Erc7730ProgramPath, RejectsMissingTargetAndMalformedSteps) {
  const std::vector<uint8_t> one = {0, 1, 1, 1, 0xff, 0xff, 2};
  Erc7730ProgramPath loader;
  erc7730_program_path_begin(&loader, (uint32_t)one.size(), 1);
  EXPECT_FALSE(erc7730_program_path_feed(&loader, 0, one.data(), one.size()));

  const std::vector<uint8_t> duplicate_all = {
      0, 1, 1, 2, 0xff, 0xff, 2, 2,
  };
  erc7730_program_path_begin(&loader, (uint32_t)duplicate_all.size(), 0);
  EXPECT_FALSE(erc7730_program_path_feed(&loader, 0, duplicate_all.data(),
                                         duplicate_all.size()));
}

TEST(Erc7730ProgramString, SelectsOneBoundedStringAcrossChunks) {
  const std::vector<uint8_t> section = {
      0, 3, 0, 1, 'A', 0, 4, 'T', 'e', 's', 't', 0, 3, 0xe2, 0x82, 0xac};
  for (size_t chunk : {1u, 3u, 64u}) {
    Erc7730ProgramString loader;
    erc7730_program_string_begin(&loader, section.size(), 1);
    for (size_t offset = 0; offset < section.size();) {
      const size_t length = std::min(chunk, section.size() - offset);
      ASSERT_TRUE(erc7730_program_string_feed(&loader, offset,
                                              section.data() + offset, length));
      offset += length;
    }
    const char* value = nullptr;
    size_t length = 0;
    ASSERT_TRUE(erc7730_program_string_complete(&loader, &value, &length));
    EXPECT_EQ(length, 4u);
    EXPECT_STREQ(value, "Test");
  }
}

TEST(Erc7730ProgramString, RejectsMissingOversizedAndTruncatedValues) {
  std::vector<uint8_t> section = {0, 1, 0, 1, 'A'};
  Erc7730ProgramString loader;
  erc7730_program_string_begin(&loader, section.size(), 1);
  EXPECT_FALSE(
      erc7730_program_string_feed(&loader, 0, section.data(), section.size()));

  section = {0, 1, 0, ERC7730_PROGRAM_MAX_STRING_LENGTH + 1};
  erc7730_program_string_begin(&loader, section.size(), 0);
  EXPECT_FALSE(
      erc7730_program_string_feed(&loader, 0, section.data(), section.size()));

  section = {0, 1, 0, 2, 'A'};
  erc7730_program_string_begin(&loader, section.size(), 0);
  EXPECT_FALSE(
      erc7730_program_string_feed(&loader, 0, section.data(), section.size()));
}

TEST(Erc7730ProgramDisplay, SelectsInstructionAcrossChunks) {
  const std::vector<uint8_t> section = {
      0, 3, 1, 0, 0, 2,  0xff, 0xff, 0xff, 0xff, 4,    0,    0,
      3, 0, 7, 0, 9, 10, 0,    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  };
  for (size_t chunk : {1u, 7u, 64u}) {
    Erc7730ProgramDisplay loader;
    erc7730_program_display_begin(&loader, section.size(), 1);
    for (size_t offset = 0; offset < section.size();) {
      const size_t length = std::min(chunk, section.size() - offset);
      ASSERT_TRUE(erc7730_program_display_feed(
          &loader, offset, section.data() + offset, length));
      offset += length;
    }
    Erc7730DisplayInstruction instruction;
    uint16_t count = 0;
    ASSERT_TRUE(
        erc7730_program_display_complete(&loader, &instruction, &count));
    EXPECT_EQ(count, 3u);
    EXPECT_EQ(instruction.opcode, 4u);
    EXPECT_EQ(instruction.a, 3u);
    EXPECT_EQ(instruction.b, 7u);
    EXPECT_EQ(instruction.c, 9u);
  }
}

TEST(Erc7730ProgramDisplay, RejectsMissingTargetAndLengthMismatch) {
  std::vector<uint8_t> section = {0,    1,    10,   0,    0xff,
                                  0xff, 0xff, 0xff, 0xff, 0xff};
  Erc7730ProgramDisplay loader;
  erc7730_program_display_begin(&loader, section.size(), 1);
  EXPECT_FALSE(
      erc7730_program_display_feed(&loader, 0, section.data(), section.size()));
  section.push_back(0);
  erc7730_program_display_begin(&loader, section.size(), 0);
  EXPECT_TRUE(loader.failed);
}

TEST(Erc7730ProgramFormatter, SelectsTypedArgumentsAcrossChunks) {
  const std::vector<uint8_t> section = {
      0, 2, 1, 0, 1, 1, 1, 0, 3, 3, 2, 3, 1, 1, 0, 4, 2, 2, 0, 7, 11, 3, 0, 9,
  };
  for (size_t chunk : {1u, 4u, 64u}) {
    Erc7730ProgramFormatter loader;
    erc7730_program_formatter_begin(&loader, section.size(), 1);
    for (size_t offset = 0; offset < section.size();) {
      const size_t length = std::min(chunk, section.size() - offset);
      ASSERT_TRUE(erc7730_program_formatter_feed(
          &loader, offset, section.data() + offset, length));
      offset += length;
    }
    Erc7730Formatter formatter;
    ASSERT_TRUE(erc7730_program_formatter_complete(&loader, &formatter));
    EXPECT_EQ(formatter.kind, 3u);
    EXPECT_EQ(formatter.flags, 2u);
    ASSERT_EQ(formatter.argument_count, 3u);
    EXPECT_EQ(formatter.arguments[0].role, 1u);
    EXPECT_EQ(formatter.arguments[0].index, 4u);
    EXPECT_EQ(formatter.arguments[2].source, 3u);
    EXPECT_EQ(formatter.arguments[2].index, 9u);
  }
}

TEST(Erc7730ProgramFormatter, RejectsMissingAndExcessArguments) {
  std::vector<uint8_t> section = {0, 1, 1, 0, 0};
  Erc7730ProgramFormatter loader;
  erc7730_program_formatter_begin(&loader, section.size(), 0);
  EXPECT_FALSE(erc7730_program_formatter_feed(&loader, 0, section.data(),
                                              section.size()));
  section[4] = ERC7730_FORMATTER_MAX_ARGUMENTS + 1;
  erc7730_program_formatter_begin(&loader, section.size(), 0);
  EXPECT_FALSE(erc7730_program_formatter_feed(&loader, 0, section.data(),
                                              section.size()));
}

TEST(Erc7730ProgramCondition, SelectsFixedConditionAcrossChunks) {
  const std::vector<uint8_t> section = {
      0, 2, 1, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 6, 0, 3, 0, 7, 1, 0, 0,
  };
  for (size_t chunk : {1u, 5u, 64u}) {
    Erc7730ProgramCondition loader;
    erc7730_program_condition_begin(&loader, section.size(), 1);
    for (size_t offset = 0; offset < section.size();) {
      const size_t length = std::min(chunk, section.size() - offset);
      ASSERT_TRUE(erc7730_program_condition_feed(
          &loader, offset, section.data() + offset, length));
      offset += length;
    }
    Erc7730Condition condition;
    ASSERT_TRUE(erc7730_program_condition_complete(&loader, &condition));
    EXPECT_EQ(condition.opcode, 6u);
    EXPECT_EQ(condition.path, 3u);
    EXPECT_EQ(condition.literal_set, 7u);
    EXPECT_EQ(condition.flags, 1u);
  }
}

TEST(Erc7730ProgramCondition, RejectsMissingTargetAndBadLength) {
  std::vector<uint8_t> section = {0, 1, 1, 0xff, 0xff, 0xff, 0xff, 0, 0, 0};
  Erc7730ProgramCondition loader;
  erc7730_program_condition_begin(&loader, section.size(), 1);
  EXPECT_FALSE(erc7730_program_condition_feed(&loader, 0, section.data(),
                                              section.size()));
  section.push_back(0);
  erc7730_program_condition_begin(&loader, section.size(), 0);
  EXPECT_TRUE(loader.failed);
}

TEST(Erc7730ProgramLiteral, SelectsTypedLiteralAcrossChunks) {
  const std::vector<uint8_t> section = {
      0, 3, 1, 0, 1, 7, 3, 0, 3, 0xaa, 0xbb, 0xcc, 6, 0, 1, 1,
  };
  for (size_t chunk : {1u, 5u, 64u}) {
    Erc7730ProgramLiteral loader;
    erc7730_program_literal_begin(&loader, section.size(), 1);
    for (size_t offset = 0; offset < section.size();) {
      const size_t length = std::min(chunk, section.size() - offset);
      ASSERT_TRUE(erc7730_program_literal_feed(
          &loader, offset, section.data() + offset, length));
      offset += length;
    }
    Erc7730Literal literal;
    ASSERT_TRUE(erc7730_program_literal_complete(&loader, &literal));
    EXPECT_EQ(literal.kind, 3u);
    ASSERT_EQ(literal.length, 3u);
    EXPECT_EQ(literal.value[0], 0xaau);
    EXPECT_EQ(literal.value[2], 0xccu);
  }
}

TEST(Erc7730ProgramLiteral, RejectsMissingOversizedAndTruncatedValues) {
  std::vector<uint8_t> section = {0, 1, 1, 0, 1, 7};
  Erc7730ProgramLiteral loader;
  erc7730_program_literal_begin(&loader, section.size(), 1);
  EXPECT_FALSE(
      erc7730_program_literal_feed(&loader, 0, section.data(), section.size()));
  section = {0, 1, 3, 1, 3};
  erc7730_program_literal_begin(&loader, section.size(), 0);
  EXPECT_FALSE(
      erc7730_program_literal_feed(&loader, 0, section.data(), section.size()));
  section = {0, 1, 3, 0, 2, 0xaa};
  erc7730_program_literal_begin(&loader, section.size(), 0);
  EXPECT_FALSE(
      erc7730_program_literal_feed(&loader, 0, section.data(), section.size()));
}
