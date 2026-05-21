# Convenience targets — mirrors CI jobs so failures are caught locally.
#
# CI pins clang-format-20. Use that version if available, otherwise fall back.
# To install: brew install llvm@20  or  apt-get install clang-format-20
CLANG_FORMAT ?= $(shell command -v clang-format-20 2>/dev/null || echo clang-format)

# Directories and exclusions must match .github/workflows/ci.yml lint-format job.
LINT_DIRS := include/keepkey lib/firmware lib/board lib/transport/src
LINT_SOURCES := $(shell find $(LINT_DIRS) -name '*.c' -o -name '*.h' 2>/dev/null \
                | grep -v generated | grep -v '\.pb\.')

.PHONY: lint format help

## lint: Check formatting (same rules as CI). Exits non-zero on any violation.
lint:
	@echo "clang-format version: $$($(CLANG_FORMAT) --version)"
	@FAILED=0; \
	for f in $(LINT_SOURCES); do \
	  if ! $(CLANG_FORMAT) --style=file --dry-run --Werror "$$f" 2>/dev/null; then \
	    echo "  NEEDS FORMAT: $$f"; \
	    FAILED=1; \
	  fi; \
	done; \
	if [ "$$FAILED" = "1" ]; then \
	  echo ""; \
	  echo "Run 'make format' to fix all files."; \
	  exit 1; \
	else \
	  echo "All files pass clang-format check."; \
	fi

## format: Auto-fix formatting in-place for all source files.
format:
	@echo "Formatting $(LINT_DIRS)..."
	@for f in $(LINT_SOURCES); do \
	  $(CLANG_FORMAT) --style=file -i "$$f"; \
	done
	@echo "Done. Review changes with: git diff"

## help: List available targets.
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  make /'
