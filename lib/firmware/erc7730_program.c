#include "keepkey/firmware/erc7730_program.h"

#include <string.h>

#include "memzero.h"

static uint32_t read_be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}

static uint16_t read_be16(const uint8_t* p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

void erc7730_program_index_begin(Erc7730ProgramIndex* index,
                                 uint32_t program_length) {
  if (!index) return;
  memzero(index, sizeof(*index));
  index->program_length = program_length;
  if (program_length < ERC7730_PROGRAM_HEADER_SIZE ||
      program_length > ERC7730_PROGRAM_MAX_SIZE) {
    index->failed = true;
  }
}

bool erc7730_program_index_feed(Erc7730ProgramIndex* index,
                                uint32_t program_offset, const uint8_t* data,
                                size_t data_len) {
  if (!index || !data || data_len == 0 || index->failed || index->complete ||
      program_offset != index->received ||
      data_len > index->program_length - index->received) {
    if (index) index->failed = true;
    return false;
  }

  for (size_t i = 0; i < data_len; i++, index->received++) {
    const uint8_t byte = data[i];
    if (index->received < ERC7730_PROGRAM_HEADER_SIZE) {
      if (index->received == ERC7730_PROGRAM_HEADER_SIZE - 1u)
        index->declared_sections = byte;
      continue;
    }
    if (index->section_remaining != 0) {
      index->section_remaining--;
      continue;
    }

    index->section_header[index->section_header_received++] = byte;
    if (index->section_header_received != sizeof(index->section_header))
      continue;
    const uint8_t type = index->section_header[0];
    const uint32_t length = read_be32(index->section_header + 1);
    const uint32_t payload_offset = index->received + 1u;
    if (type == 0 || type > ERC7730_PROGRAM_MAX_SECTIONS ||
        type <= index->last_section ||
        length > index->program_length - payload_offset) {
      index->failed = true;
      return false;
    }
    index->sections[type].offset = payload_offset;
    index->sections[type].length = length;
    index->last_section = type;
    index->sections_seen++;
    index->section_remaining = length;
    index->section_header_received = 0;
  }

  if (index->received == index->program_length) {
    index->complete = !index->failed && index->section_remaining == 0 &&
                      index->section_header_received == 0 &&
                      index->sections_seen == index->declared_sections;
    if (!index->complete) index->failed = true;
  }
  return !index->failed;
}

bool erc7730_program_index_complete(const Erc7730ProgramIndex* index) {
  return index && index->complete && !index->failed;
}

bool erc7730_program_index_section(const Erc7730ProgramIndex* index,
                                   uint8_t section,
                                   Erc7730ProgramSection* result) {
  if (!erc7730_program_index_complete(index) || !result || section == 0 ||
      section > ERC7730_PROGRAM_MAX_SECTIONS ||
      index->sections[section].length == 0) {
    return false;
  }
  *result = index->sections[section];
  return true;
}

bool erc7730_program_index_known_section(const Erc7730ProgramIndex* index,
                                         uint8_t section,
                                         Erc7730ProgramSection* result) {
  if (!index || index->failed || !result || section == 0 ||
      section > ERC7730_PROGRAM_MAX_SECTIONS ||
      index->sections[section].length == 0)
    return false;
  *result = index->sections[section];
  return true;
}

void erc7730_program_index_clear(Erc7730ProgramIndex* index) {
  if (index) memzero(index, sizeof(*index));
}

void erc7730_program_abi_begin(Erc7730ProgramAbi* abi,
                               uint32_t section_length) {
  if (!abi) return;
  memzero(abi, sizeof(*abi));
  abi->section_length = section_length;
  if (section_length < 11 || section_length > 2 + 9 * ERC7730_ABI_MAX_NODES)
    abi->failed = true;
}

bool erc7730_program_abi_feed(Erc7730ProgramAbi* abi, uint32_t section_offset,
                              const uint8_t* data, size_t data_len) {
  if (!abi || !data || data_len == 0 || abi->failed || abi->complete ||
      section_offset != abi->received ||
      data_len > abi->section_length - abi->received) {
    if (abi) abi->failed = true;
    return false;
  }
  for (size_t i = 0; i < data_len; i++, abi->received++) {
    const uint8_t byte = data[i];
    if (abi->received < 2) {
      abi->entry[abi->received] = byte;
      if (abi->received == 1) {
        abi->node_count = read_be16(abi->entry);
        if (abi->node_count == 0 || abi->node_count > ERC7730_ABI_MAX_NODES ||
            abi->section_length != 2u + (uint32_t)abi->node_count * 9u) {
          abi->failed = true;
          return false;
        }
      }
      continue;
    }

    abi->entry[abi->entry_received++] = byte;
    if (abi->entry_received == sizeof(abi->entry)) {
      Erc7730AbiNode* node = &abi->nodes[abi->node_index++];
      node->kind = abi->entry[0];
      node->size = read_be16(abi->entry + 1);
      node->first_child = read_be16(abi->entry + 3);
      node->child_count = read_be16(abi->entry + 5);
      node->array_length = read_be16(abi->entry + 7);
      abi->entry_received = 0;
    }
  }

  if (abi->received == abi->section_length) {
    Erc7730AbiProgram program = {abi->nodes, abi->node_count, 0};
    abi->complete = abi->node_index == abi->node_count &&
                    abi->entry_received == 0 &&
                    erc7730_abi_validate_program(&program) == ERC7730_ABI_OK;
    if (!abi->complete) abi->failed = true;
  }
  return !abi->failed;
}

bool erc7730_program_abi_complete(const Erc7730ProgramAbi* abi,
                                  Erc7730AbiProgram* program) {
  if (!abi || !program || !abi->complete || abi->failed) return false;
  program->nodes = abi->nodes;
  program->node_count = abi->node_count;
  program->root = 0;
  return true;
}

void erc7730_program_abi_clear(Erc7730ProgramAbi* abi) {
  if (abi) memzero(abi, sizeof(*abi));
}

void erc7730_program_loader_begin(Erc7730ProgramLoader* loader,
                                  uint32_t program_length) {
  if (!loader) return;
  memzero(loader, sizeof(*loader));
  erc7730_program_index_begin(&loader->index, program_length);
  loader->failed = loader->index.failed;
}

bool erc7730_program_loader_feed(Erc7730ProgramLoader* loader,
                                 uint32_t program_offset, const uint8_t* data,
                                 size_t data_len) {
  if (!loader || !data || data_len == 0 || loader->failed ||
      data_len > UINT32_MAX - program_offset ||
      !erc7730_program_index_feed(&loader->index, program_offset, data,
                                  data_len)) {
    if (loader) loader->failed = true;
    return false;
  }

  Erc7730ProgramSection section;
  if (!erc7730_program_index_known_section(
          &loader->index, ERC7730_PROGRAM_SECTION_ABI, &section))
    return true;
  if (!loader->abi_started) {
    erc7730_program_abi_begin(&loader->abi, section.length);
    loader->abi_started = true;
    if (loader->abi.failed) {
      loader->failed = true;
      return false;
    }
  }

  const uint32_t chunk_end = program_offset + (uint32_t)data_len;
  const uint32_t section_end = section.offset + section.length;
  const uint32_t overlap_start =
      program_offset > section.offset ? program_offset : section.offset;
  const uint32_t overlap_end =
      chunk_end < section_end ? chunk_end : section_end;
  if (overlap_start < overlap_end &&
      !erc7730_program_abi_feed(&loader->abi, overlap_start - section.offset,
                                data + (overlap_start - program_offset),
                                overlap_end - overlap_start)) {
    loader->failed = true;
    return false;
  }
  return true;
}

bool erc7730_program_loader_complete(const Erc7730ProgramLoader* loader,
                                     Erc7730AbiProgram* program) {
  return loader && !loader->failed && loader->abi_started &&
         erc7730_program_index_complete(&loader->index) &&
         erc7730_program_abi_complete(&loader->abi, program);
}

void erc7730_program_loader_clear(Erc7730ProgramLoader* loader) {
  if (loader) memzero(loader, sizeof(*loader));
}

static void path_finish_entry(Erc7730ProgramPath* path) {
  if (path->path_index == path->target_index) path->selected_found = true;
  path->path_index++;
  path->header_received = 0;
  path->current_step_count = 0;
  path->step_index = 0;
  path->step_opcode = 0;
  path->step_flags = 0;
  path->step_value_received = 0;
  path->step_value_length = 0;
  path->full_array_seen = false;
}

static void path_finish_step(Erc7730ProgramPath* path) {
  path->step_index++;
  path->step_opcode = 0;
  path->step_flags = 0;
  path->step_value_received = 0;
  path->step_value_length = 0;
  if (path->step_index == path->current_step_count) path_finish_entry(path);
}

void erc7730_program_path_begin(Erc7730ProgramPath* path,
                                uint32_t section_length,
                                uint16_t target_index) {
  if (!path) return;
  memzero(path, sizeof(*path));
  path->section_length = section_length;
  path->target_index = target_index;
  if (section_length < 2) path->failed = true;
}

bool erc7730_program_path_feed(Erc7730ProgramPath* path,
                               uint32_t section_offset, const uint8_t* data,
                               size_t data_len) {
  if (!path || !data || data_len == 0 || path->failed || path->complete ||
      section_offset != path->received ||
      data_len > path->section_length - path->received) {
    if (path) path->failed = true;
    return false;
  }
  for (size_t i = 0; i < data_len; i++, path->received++) {
    const uint8_t byte = data[i];
    if (path->received < 2) {
      path->scratch[path->received] = byte;
      if (path->received == 1) {
        path->path_count = read_be16(path->scratch);
        if (path->path_count > 64 || path->target_index >= path->path_count) {
          path->failed = true;
          return false;
        }
      }
      continue;
    }

    if (path->header_received < 4) {
      path->scratch[path->header_received++] = byte;
      if (path->header_received != 4) continue;
      const uint8_t source = path->scratch[0];
      const uint8_t steps = path->scratch[1];
      const uint16_t source_index = read_be16(path->scratch + 2);
      if (source < 1 || source > 3 || steps > ERC7730_ABI_MAX_PATH ||
          (source == 1 && (source_index != UINT16_MAX || steps == 0)) ||
          (source != 1 && steps != 0) ||
          (source == 2 && (source_index == 0 || source_index > 6)) ||
          (source == 3 && source_index == UINT16_MAX)) {
        path->failed = true;
        return false;
      }
      if (path->path_index == path->target_index) {
        path->selected.source = source;
        path->selected.step_count = steps;
        path->selected.source_index = source_index;
      }
      path->current_step_count = steps;
      if (steps == 0) path_finish_entry(path);
      continue;
    }

    if (path->step_opcode == 0) {
      path->step_opcode = byte;
      if (path->path_index == path->target_index)
        path->selected.steps[path->step_index].opcode = byte;
      if (byte == 1) {
        path->step_value_length = 4;
      } else if (byte == 2) {
        if (path->full_array_seen) {
          path->failed = true;
          return false;
        }
        path->full_array_seen = true;
        path_finish_step(path);
      } else if (byte == 3) {
        if (path->step_index + 1u != path->current_step_count) {
          path->failed = true;
          return false;
        }
      } else {
        path->failed = true;
        return false;
      }
      continue;
    }

    if (path->step_opcode == 3 && path->step_flags == 0) {
      if (byte == 0 || (byte & (uint8_t)~3u) != 0) {
        path->failed = true;
        return false;
      }
      path->step_flags = byte;
      path->step_value_length =
          (uint8_t)(((byte & 1u) ? 4u : 0u) + ((byte & 2u) ? 4u : 0u));
      if (path->path_index == path->target_index)
        path->selected.steps[path->step_index].flags = byte;
      if (path->step_value_length == 0) path_finish_step(path);
      continue;
    }

    path->scratch[path->step_value_received++] = byte;
    if (path->step_value_received != path->step_value_length) continue;
    if (path->path_index == path->target_index) {
      Erc7730PathStep* selected = &path->selected.steps[path->step_index];
      if (path->step_opcode == 1) {
        selected->first = (int32_t)read_be32(path->scratch);
      } else {
        uint8_t value_offset = 0;
        if ((path->step_flags & 1u) != 0) {
          selected->first = (int32_t)read_be32(path->scratch);
          value_offset = 4;
        }
        if ((path->step_flags & 2u) != 0)
          selected->second = (int32_t)read_be32(path->scratch + value_offset);
      }
    }
    path_finish_step(path);
  }

  if (path->received == path->section_length) {
    path->complete = !path->failed && path->path_index == path->path_count &&
                     path->header_received == 0 && path->step_opcode == 0 &&
                     path->selected_found;
    if (!path->complete) path->failed = true;
  }
  return !path->failed;
}

bool erc7730_program_path_complete(const Erc7730ProgramPath* path,
                                   Erc7730Path* result) {
  if (!path || !result || !path->complete || path->failed) return false;
  *result = path->selected;
  return true;
}

void erc7730_program_path_clear(Erc7730ProgramPath* path) {
  if (path) memzero(path, sizeof(*path));
}

void erc7730_program_string_begin(Erc7730ProgramString* string,
                                  uint32_t section_length,
                                  uint16_t target_index) {
  if (!string) return;
  memzero(string, sizeof(*string));
  string->section_length = section_length;
  string->target_index = target_index;
  if (section_length < 2) string->failed = true;
}

bool erc7730_program_string_feed(Erc7730ProgramString* string,
                                 uint32_t section_offset, const uint8_t* data,
                                 size_t data_len) {
  if (!string || !data || data_len == 0 || string->failed || string->complete ||
      section_offset != string->received ||
      data_len > string->section_length - string->received) {
    if (string) string->failed = true;
    return false;
  }
  for (size_t i = 0; i < data_len; i++, string->received++) {
    const uint8_t byte = data[i];
    if (string->received < 2) {
      string->header[string->received] = byte;
      if (string->received == 1) {
        string->string_count = read_be16(string->header);
        if (string->string_count > 96 ||
            string->target_index >= string->string_count) {
          string->failed = true;
          return false;
        }
      }
      continue;
    }
    if (string->current_length == 0) {
      string->header[string->header_received++] = byte;
      if (string->header_received != 2) continue;
      string->current_length = read_be16(string->header);
      string->header_received = 0;
      if (string->current_length == 0 ||
          string->current_length > ERC7730_PROGRAM_MAX_STRING_LENGTH) {
        string->failed = true;
        return false;
      }
      continue;
    }
    if (string->string_index == string->target_index)
      string->value[string->current_received] = byte;
    string->current_received++;
    if (string->current_received == string->current_length) {
      if (string->string_index == string->target_index) {
        string->value[string->current_length] = 0;
        string->selected_length = string->current_length;
        string->selected_found = true;
      }
      string->string_index++;
      string->current_length = 0;
      string->current_received = 0;
    }
  }
  if (string->received == string->section_length) {
    string->complete = !string->failed && string->selected_found &&
                       string->string_index == string->string_count &&
                       string->current_length == 0 &&
                       string->header_received == 0;
    if (!string->complete) string->failed = true;
  }
  return !string->failed;
}

bool erc7730_program_string_complete(const Erc7730ProgramString* string,
                                     const char** value, size_t* value_len) {
  if (!string || !value || !value_len || !string->complete || string->failed)
    return false;
  *value = (const char*)string->value;
  *value_len = string->selected_length;
  return true;
}

void erc7730_program_string_clear(Erc7730ProgramString* string) {
  if (string) memzero(string, sizeof(*string));
}

void erc7730_program_display_begin(Erc7730ProgramDisplay* display,
                                   uint32_t section_length,
                                   uint16_t target_index) {
  if (!display) return;
  memzero(display, sizeof(*display));
  display->section_length = section_length;
  display->target_index = target_index;
  if (section_length < 10 || ((section_length - 2u) % 8u) != 0)
    display->failed = true;
}

bool erc7730_program_display_feed(Erc7730ProgramDisplay* display,
                                  uint32_t section_offset, const uint8_t* data,
                                  size_t data_len) {
  if (!display || !data || data_len == 0 || display->failed ||
      display->complete || section_offset != display->received ||
      data_len > display->section_length - display->received) {
    if (display) display->failed = true;
    return false;
  }
  for (size_t i = 0; i < data_len; i++, display->received++) {
    const uint8_t byte = data[i];
    if (display->received < 2) {
      display->entry[display->received] = byte;
      if (display->received == 1) {
        display->instruction_count = read_be16(display->entry);
        if (display->instruction_count == 0 ||
            display->instruction_count > 64 ||
            display->target_index >= display->instruction_count ||
            display->section_length !=
                2u + (uint32_t)display->instruction_count * 8u) {
          display->failed = true;
          return false;
        }
      }
      continue;
    }
    display->entry[display->entry_received++] = byte;
    if (display->entry_received != sizeof(display->entry)) continue;
    if (display->instruction_index == display->target_index) {
      display->selected.opcode = display->entry[0];
      display->selected.flags = display->entry[1];
      display->selected.a = read_be16(display->entry + 2);
      display->selected.b = read_be16(display->entry + 4);
      display->selected.c = read_be16(display->entry + 6);
    }
    display->instruction_index++;
    display->entry_received = 0;
  }
  if (display->received == display->section_length) {
    display->complete =
        !display->failed &&
        display->instruction_index == display->instruction_count &&
        display->entry_received == 0;
    if (!display->complete) display->failed = true;
  }
  return !display->failed;
}

bool erc7730_program_display_complete(const Erc7730ProgramDisplay* display,
                                      Erc7730DisplayInstruction* instruction,
                                      uint16_t* instruction_count) {
  if (!display || !instruction || !instruction_count || !display->complete ||
      display->failed)
    return false;
  *instruction = display->selected;
  *instruction_count = display->instruction_count;
  return true;
}

void erc7730_program_display_clear(Erc7730ProgramDisplay* display) {
  if (display) memzero(display, sizeof(*display));
}

void erc7730_program_formatter_begin(Erc7730ProgramFormatter* formatter,
                                     uint32_t section_length,
                                     uint16_t target_index) {
  if (!formatter) return;
  memzero(formatter, sizeof(*formatter));
  formatter->section_length = section_length;
  formatter->target_index = target_index;
  if (section_length < 2) formatter->failed = true;
}

bool erc7730_program_formatter_feed(Erc7730ProgramFormatter* formatter,
                                    uint32_t section_offset,
                                    const uint8_t* data, size_t data_len) {
  if (!formatter || !data || data_len == 0 || formatter->failed ||
      formatter->complete || section_offset != formatter->received ||
      data_len > formatter->section_length - formatter->received) {
    if (formatter) formatter->failed = true;
    return false;
  }
  for (size_t i = 0; i < data_len; i++, formatter->received++) {
    const uint8_t byte = data[i];
    if (formatter->received < 2) {
      formatter->scratch[formatter->received] = byte;
      if (formatter->received == 1) {
        formatter->formatter_count = read_be16(formatter->scratch);
        if (formatter->formatter_count > 64 ||
            formatter->target_index >= formatter->formatter_count) {
          formatter->failed = true;
          return false;
        }
      }
      continue;
    }
    if (formatter->header_received < 3) {
      formatter->scratch[formatter->header_received++] = byte;
      if (formatter->header_received != 3) continue;
      if (formatter->scratch[2] == 0 ||
          formatter->scratch[2] > ERC7730_FORMATTER_MAX_ARGUMENTS) {
        formatter->failed = true;
        return false;
      }
      formatter->current_argument_count = formatter->scratch[2];
      if (formatter->formatter_index == formatter->target_index) {
        formatter->selected.kind = formatter->scratch[0];
        formatter->selected.flags = formatter->scratch[1];
        formatter->selected.argument_count = formatter->scratch[2];
      }
      continue;
    }
    formatter->scratch[formatter->argument_received++] = byte;
    if (formatter->argument_received != 4) continue;
    if (formatter->formatter_index == formatter->target_index) {
      Erc7730FormatterArgument* argument =
          &formatter->selected.arguments[formatter->argument_index];
      argument->role = formatter->scratch[0];
      argument->source = formatter->scratch[1];
      argument->index = read_be16(formatter->scratch + 2);
    }
    formatter->argument_received = 0;
    formatter->argument_index++;
    if (formatter->argument_index == formatter->current_argument_count) {
      formatter->formatter_index++;
      formatter->header_received = 0;
      formatter->current_argument_count = 0;
      formatter->argument_index = 0;
    }
  }
  if (formatter->received == formatter->section_length) {
    formatter->complete =
        !formatter->failed &&
        formatter->formatter_index == formatter->formatter_count &&
        formatter->header_received == 0 && formatter->argument_received == 0;
    if (!formatter->complete) formatter->failed = true;
  }
  return !formatter->failed;
}

bool erc7730_program_formatter_complete(
    const Erc7730ProgramFormatter* formatter, Erc7730Formatter* result) {
  if (!formatter || !result || !formatter->complete || formatter->failed)
    return false;
  *result = formatter->selected;
  return true;
}

void erc7730_program_formatter_clear(Erc7730ProgramFormatter* formatter) {
  if (formatter) memzero(formatter, sizeof(*formatter));
}

void erc7730_program_condition_begin(Erc7730ProgramCondition* condition,
                                     uint32_t section_length,
                                     uint16_t target_index) {
  if (!condition) return;
  memzero(condition, sizeof(*condition));
  condition->section_length = section_length;
  condition->target_index = target_index;
  if (section_length < 2 || ((section_length - 2u) % 8u) != 0)
    condition->failed = true;
}

bool erc7730_program_condition_feed(Erc7730ProgramCondition* condition,
                                    uint32_t section_offset,
                                    const uint8_t* data, size_t data_len) {
  if (!condition || !data || data_len == 0 || condition->failed ||
      condition->complete || section_offset != condition->received ||
      data_len > condition->section_length - condition->received) {
    if (condition) condition->failed = true;
    return false;
  }
  for (size_t i = 0; i < data_len; i++, condition->received++) {
    const uint8_t byte = data[i];
    if (condition->received < 2) {
      condition->entry[condition->received] = byte;
      if (condition->received == 1) {
        condition->condition_count = read_be16(condition->entry);
        if (condition->condition_count > 32 ||
            condition->target_index >= condition->condition_count ||
            condition->section_length !=
                2u + (uint32_t)condition->condition_count * 8u) {
          condition->failed = true;
          return false;
        }
      }
      continue;
    }
    condition->entry[condition->entry_received++] = byte;
    if (condition->entry_received != sizeof(condition->entry)) continue;
    if (condition->condition_index == condition->target_index) {
      condition->selected.opcode = condition->entry[0];
      condition->selected.path = read_be16(condition->entry + 1);
      condition->selected.literal_set = read_be16(condition->entry + 3);
      condition->selected.flags = condition->entry[5];
    }
    condition->condition_index++;
    condition->entry_received = 0;
  }
  if (condition->received == condition->section_length) {
    condition->complete =
        !condition->failed &&
        condition->condition_index == condition->condition_count &&
        condition->entry_received == 0;
    if (!condition->complete) condition->failed = true;
  }
  return !condition->failed;
}

bool erc7730_program_condition_complete(
    const Erc7730ProgramCondition* condition, Erc7730Condition* result) {
  if (!condition || !result || !condition->complete || condition->failed)
    return false;
  *result = condition->selected;
  return true;
}

void erc7730_program_condition_clear(Erc7730ProgramCondition* condition) {
  if (condition) memzero(condition, sizeof(*condition));
}

void erc7730_program_token_metadata_begin(
    Erc7730ProgramTokenMetadata* metadata, uint32_t section_length,
    uint64_t chain_id, const uint8_t address[20]) {
  if (!metadata) return;
  memzero(metadata, sizeof(*metadata));
  metadata->section_length = section_length;
  metadata->target_chain_id = chain_id;
  metadata->target_kind = 3;
  if (address) memcpy(metadata->target_address, address, 20);
  if (!address || chain_id == 0 || section_length < 2) metadata->failed = true;
}

void erc7730_program_network_metadata_begin(
    Erc7730ProgramTokenMetadata* metadata, uint32_t section_length,
    uint64_t chain_id) {
  if (!metadata) return;
  memzero(metadata, sizeof(*metadata));
  metadata->section_length = section_length;
  metadata->target_chain_id = chain_id;
  metadata->target_kind = 4;
  if (chain_id == 0 || section_length < 2) metadata->failed = true;
}

bool erc7730_program_token_metadata_feed(
    Erc7730ProgramTokenMetadata* metadata, uint32_t section_offset,
    const uint8_t* data, size_t data_len) {
  if (!metadata || !data || data_len == 0 || metadata->failed ||
      metadata->complete || section_offset != metadata->received ||
      data_len > metadata->section_length - metadata->received) {
    if (metadata) metadata->failed = true;
    return false;
  }
  for (size_t i = 0; i < data_len; i++, metadata->received++) {
    const uint8_t byte = data[i];
    if (metadata->received < 2) {
      metadata->header[metadata->received] = byte;
      if (metadata->received == 1) {
        metadata->record_count = read_be16(metadata->header);
        if (metadata->record_count > 64) {
          metadata->failed = true;
          return false;
        }
      }
      continue;
    }
    if (metadata->current_length == 0) {
      metadata->header[metadata->header_received++] = byte;
      if (metadata->header_received != 3) continue;
      metadata->current_length = read_be16(metadata->header + 1);
      metadata->header_received = 0;
      if (metadata->current_length == 0) {
        metadata->failed = true;
        return false;
      }
      continue;
    }
    const uint16_t expected_length = metadata->target_kind == 3 ? 31 : 13;
    if (metadata->header[0] == metadata->target_kind &&
        metadata->current_length == expected_length)
      metadata->payload[metadata->current_received] = byte;
    metadata->current_received++;
    if (metadata->current_received != metadata->current_length) continue;
    if (metadata->header[0] == metadata->target_kind &&
        metadata->current_length == expected_length) {
      uint64_t chain_id = 0;
      for (size_t j = 0; j < 8; j++)
        chain_id = (chain_id << 8) | metadata->payload[j];
      if (chain_id == metadata->target_chain_id &&
          (metadata->target_kind == 4 ||
           memcmp(metadata->payload + 8, metadata->target_address, 20) == 0)) {
        if (metadata->selected_found) {
          metadata->failed = true;
          return false;
        }
        const size_t ticker_offset = metadata->target_kind == 3 ? 28 : 10;
        metadata->selected.ticker_string =
            read_be16(metadata->payload + ticker_offset);
        metadata->selected.decimals = metadata->payload[ticker_offset + 2];
        metadata->selected_found = true;
      }
    }
    metadata->record_index++;
    metadata->current_length = 0;
    metadata->current_received = 0;
  }
  if (metadata->received == metadata->section_length) {
    metadata->complete = !metadata->failed && metadata->selected_found &&
                         metadata->record_index == metadata->record_count &&
                         metadata->current_length == 0 &&
                         metadata->header_received == 0;
    if (!metadata->complete) metadata->failed = true;
  }
  return !metadata->failed;
}

bool erc7730_program_token_metadata_complete(
    const Erc7730ProgramTokenMetadata* metadata,
    Erc7730TokenMetadata* result) {
  if (!metadata || !result || !metadata->complete || metadata->failed)
    return false;
  *result = metadata->selected;
  return true;
}

void erc7730_program_literal_begin(Erc7730ProgramLiteral* literal,
                                   uint32_t section_length,
                                   uint16_t target_index) {
  if (!literal) return;
  memzero(literal, sizeof(*literal));
  literal->section_length = section_length;
  literal->target_index = target_index;
  if (section_length < 2) literal->failed = true;
}

bool erc7730_program_literal_feed(Erc7730ProgramLiteral* literal,
                                  uint32_t section_offset, const uint8_t* data,
                                  size_t data_len) {
  if (!literal || !data || data_len == 0 || literal->failed ||
      literal->complete || section_offset != literal->received ||
      data_len > literal->section_length - literal->received) {
    if (literal) literal->failed = true;
    return false;
  }
  for (size_t i = 0; i < data_len; i++, literal->received++) {
    const uint8_t byte = data[i];
    if (literal->received < 2) {
      literal->header[literal->received] = byte;
      if (literal->received == 1) {
        literal->literal_count = read_be16(literal->header);
        if (literal->literal_count > 64 ||
            literal->target_index >= literal->literal_count) {
          literal->failed = true;
          return false;
        }
      }
      continue;
    }
    if (literal->current_length == 0) {
      literal->header[literal->header_received++] = byte;
      if (literal->header_received != 3) continue;
      literal->current_length = read_be16(literal->header + 1);
      literal->header_received = 0;
      if (literal->current_length == 0 ||
          literal->current_length > ERC7730_LITERAL_MAX_LENGTH) {
        literal->failed = true;
        return false;
      }
      if (literal->literal_index == literal->target_index) {
        literal->selected.kind = literal->header[0];
        literal->selected.length = literal->current_length;
      }
      continue;
    }
    if (literal->literal_index == literal->target_index)
      literal->selected.value[literal->current_received] = byte;
    literal->current_received++;
    if (literal->current_received == literal->current_length) {
      literal->literal_index++;
      literal->current_length = 0;
      literal->current_received = 0;
    }
  }
  if (literal->received == literal->section_length) {
    literal->complete =
        !literal->failed && literal->literal_index == literal->literal_count &&
        literal->current_length == 0 && literal->header_received == 0;
    if (!literal->complete) literal->failed = true;
  }
  return !literal->failed;
}

bool erc7730_program_literal_complete(const Erc7730ProgramLiteral* literal,
                                      Erc7730Literal* result) {
  if (!literal || !result || !literal->complete || literal->failed)
    return false;
  *result = literal->selected;
  return true;
}

void erc7730_program_literal_clear(Erc7730ProgramLiteral* literal) {
  if (literal) memzero(literal, sizeof(*literal));
}
