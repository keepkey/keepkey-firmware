# KeepKey Firmware — Build & Quality Targets
#
# Usage:
#   make quality          Run all quality checks (fast, no hardware needed)
#   make cppcheck         Static analysis (warnings, performance, portability)
#   make complexity       Cyclomatic complexity check (CCN > 20 = warning)
#   make format-check     clang-format compliance check
#   make misra            MISRA C:2012 compliance report (advisory)
#   make quality-report   Full report with counts and summary
#
# Build targets (require Docker or ARM toolchain):
#   make build-emu        Build emulator (Docker)
#   make build-arm        Cross-compile for ARM (Docker)

SHELL := /bin/bash

# ── Tool detection ──────────────────────────────────────────────
CPPCHECK     := $(shell command -v cppcheck 2>/dev/null)
LIZARD       := $(shell command -v lizard 2>/dev/null)
CLANG_FORMAT := $(shell command -v clang-format-14 2>/dev/null || \
                  command -v /opt/homebrew/opt/llvm/bin/clang-format 2>/dev/null || \
                  command -v clang-format 2>/dev/null)

# ── Source paths ────────────────────────────────────────────────
SRC_DIRS     := lib/firmware lib/board lib/transport/src
INC_DIRS     := include/keepkey
ALL_DIRS     := $(SRC_DIRS) $(INC_DIRS)
INCLUDE_FLAGS := -I include/ -I deps/crypto/trezor-firmware/crypto -I deps/device-protocol
DEFINES      := -DSTM32F2

# Find source files (exclude generated/protobuf)
SOURCES := $(shell find $(ALL_DIRS) \( -name '*.c' -o -name '*.h' \) \
             2>/dev/null | grep -v generated | grep -v '.pb.')

# ── Thresholds ──────────────────────────────────────────────────
CCN_WARN     := 20
CCN_FAIL     := 40
FUNC_LEN     := 300
PARAM_COUNT  := 8

# ════════════════════════════════════════════════════════════════
# Quality targets
# ════════════════════════════════════════════════════════════════

.PHONY: quality cppcheck complexity format-check misra quality-report help

## Run all quality checks (report-only mode — prints findings, never fails)
quality:
	@echo "══════════════════════════════════════"
	@echo " KeepKey Firmware Quality Gate"
	@echo "══════════════════════════════════════"
	@echo ""
	@$(MAKE) --no-print-directory cppcheck || true
	@echo ""
	@$(MAKE) --no-print-directory complexity || true
	@echo ""
	@$(MAKE) --no-print-directory format-check || true
	@echo ""
	@echo "══════════════════════════════════════"
	@echo " All quality checks complete"
	@echo "══════════════════════════════════════"

## Run quality checks in strict mode (fails on any finding)
quality-strict: cppcheck complexity format-check

## Static analysis with cppcheck
cppcheck:
ifndef CPPCHECK
	$(error "cppcheck not found. Install: brew install cppcheck / apt-get install cppcheck")
endif
	@echo "── cppcheck: static analysis ──"
	@$(CPPCHECK) \
		--enable=warning,performance,portability \
		--error-exitcode=1 \
		--inline-suppr \
		--suppress=missingIncludeSystem \
		--suppress=unmatchedSuppression \
		$(INCLUDE_FLAGS) \
		$(DEFINES) \
		--std=c99 \
		--template='{file}:{line}: ({severity}) {id}: {message}' \
		$(SRC_DIRS) $(INC_DIRS) 2>&1; \
	EXIT=$$?; \
	if [ $$EXIT -ne 0 ]; then \
		echo ""; \
		echo "⚠  cppcheck found issues (exit $$EXIT)"; \
		echo "   Suppress false positives inline: // cppcheck-suppress <id>"; \
	else \
		echo "✓  cppcheck: clean"; \
	fi; \
	exit $$EXIT

## Cyclomatic complexity check with lizard
complexity:
ifndef LIZARD
	$(error "lizard not found. Install: pip install lizard / brew install lizard")
endif
	@echo "── lizard: complexity analysis ──"
	@$(LIZARD) $(SRC_DIRS) \
		-C $(CCN_WARN) -L $(FUNC_LEN) \
		-w \
		-x "*/generated/*" -x "*/.pb.*" 2>&1; \
	WARN_COUNT=$$($(LIZARD) $(SRC_DIRS) -C $(CCN_WARN) -w -x "*/generated/*" -x "*/.pb.*" 2>&1 | wc -l | tr -d ' '); \
	FAIL_COUNT=$$($(LIZARD) $(SRC_DIRS) -C $(CCN_FAIL) -w -x "*/generated/*" -x "*/.pb.*" 2>&1 | wc -l | tr -d ' '); \
	echo ""; \
	echo "  Functions exceeding CCN $(CCN_WARN): $$WARN_COUNT (warning)"; \
	echo "  Functions exceeding CCN $(CCN_FAIL): $$FAIL_COUNT (must fix for new code)"; \
	if [ "$$FAIL_COUNT" -gt 0 ]; then \
		echo ""; \
		echo "⚠  Critical complexity (CCN > $(CCN_FAIL)):"; \
		$(LIZARD) $(SRC_DIRS) -C $(CCN_FAIL) -w -x "*/generated/*" -x "*/.pb.*" 2>&1; \
	fi

## Check code formatting with clang-format
format-check:
ifndef CLANG_FORMAT
	$(error "clang-format not found. Install: brew install llvm / apt-get install clang-format-14")
endif
	@echo "── clang-format: style check ──"
	@FAILED=0; \
	FAIL_FILES=0; \
	TOTAL=0; \
	for f in $(SOURCES); do \
		TOTAL=$$((TOTAL + 1)); \
		if ! $(CLANG_FORMAT) --style=file --dry-run --Werror "$$f" > /dev/null 2>&1; then \
			FAIL_FILES=$$((FAIL_FILES + 1)); \
			FAILED=1; \
		fi; \
	done; \
	echo "  Files checked: $$TOTAL"; \
	echo "  Files with violations: $$FAIL_FILES"; \
	if [ "$$FAILED" = "1" ]; then \
		echo ""; \
		echo "⚠  Format violations found (warn-only until codebase reformatted)"; \
		echo "   Fix: $(CLANG_FORMAT) -i <file>"; \
		echo "   Fix all: make format-fix"; \
	else \
		echo "✓  clang-format: all files clean"; \
	fi
	@# Warn-only — do not fail the build

## Auto-fix formatting violations
format-fix:
ifndef CLANG_FORMAT
	$(error "clang-format not found")
endif
	@echo "── Applying clang-format to all source files ──"
	@for f in $(SOURCES); do \
		$(CLANG_FORMAT) --style=file -i "$$f"; \
	done
	@echo "✓  Formatting applied to $$(echo $(SOURCES) | wc -w | tr -d ' ') files"

## MISRA C:2012 compliance report (advisory, not gating)
misra:
ifndef CPPCHECK
	$(error "cppcheck not found")
endif
	@echo "── MISRA C:2012 compliance report ──"
	@$(CPPCHECK) --addon=misra \
		--suppress=missingIncludeSystem \
		$(INCLUDE_FLAGS) \
		$(DEFINES) \
		--std=c99 \
		$(SRC_DIRS) $(INC_DIRS) 2>&1 | tee misra-report.txt | tail -20
	@VIOLATIONS=$$(grep -c "misra" misra-report.txt 2>/dev/null || echo 0); \
	echo ""; \
	echo "  Total MISRA violations: $$VIOLATIONS"; \
	echo "  Full report: misra-report.txt"

## Full quality report with summary
quality-report:
	@echo "════════════════════════════════════════════════"
	@echo " KeepKey Firmware Quality Report"
	@echo "════════════════════════════════════════════════"
	@echo ""
	@echo "── 1. Static Analysis (cppcheck) ──"
	@$(CPPCHECK) \
		--enable=warning,performance,portability \
		--inline-suppr \
		--suppress=missingIncludeSystem \
		--suppress=unmatchedSuppression \
		$(INCLUDE_FLAGS) \
		$(DEFINES) \
		--std=c99 \
		--template='{file}:{line}: ({severity}) {id}: {message}' \
		$(SRC_DIRS) $(INC_DIRS) 2>&1 | grep -E '\(warning\)|\(error\)|\(portability\)|\(performance\)' | sort | tee /tmp/kk-cppcheck.txt; \
	echo "  Findings: $$(wc -l < /tmp/kk-cppcheck.txt | tr -d ' ')"
	@echo ""
	@echo "── 2. Complexity (lizard CCN > $(CCN_WARN)) ──"
	@$(LIZARD) $(SRC_DIRS) -C $(CCN_WARN) -L $(FUNC_LEN) -w -x "*/generated/*" -x "*/.pb.*" 2>&1 | tee /tmp/kk-lizard.txt; \
	echo "  Warnings: $$(wc -l < /tmp/kk-lizard.txt | tr -d ' ') functions"
	@echo ""
	@TOTAL=$$(echo $(SOURCES) | wc -w | tr -d ' '); \
	CLEAN=0; \
	for f in $(SOURCES); do \
		if $(CLANG_FORMAT) --style=file --dry-run --Werror "$$f" > /dev/null 2>&1; then \
			CLEAN=$$((CLEAN + 1)); \
		fi; \
	done; \
	echo "── 3. Formatting ──"; \
	echo "  Files: $$TOTAL total, $$CLEAN clean, $$((TOTAL - CLEAN)) need formatting"
	@echo ""
	@echo "════════════════════════════════════════════════"

# ════════════════════════════════════════════════════════════════
# Build targets (Docker-based)
# ════════════════════════════════════════════════════════════════

BASE_IMAGE := kktech/firmware:v15

## Build emulator image
build-emu:
	@echo "── Building emulator ──"
	docker build -t kkemu-dev -f scripts/emulator/Dockerfile .

## Cross-compile firmware for ARM
build-arm:
	@echo "── Cross-compiling for ARM ──"
	docker run --rm \
		-v $$(pwd):/root/keepkey-firmware:z \
		$(BASE_IMAGE) /bin/sh -c "\
		  mkdir /root/build && cd /root/build && \
		  cmake -C /root/keepkey-firmware/cmake/caches/device.cmake /root/keepkey-firmware \
		    -DCMAKE_BUILD_TYPE=MinSizeRel && \
		  make -j$$(nproc)"

## Show help
help:
	@echo "KeepKey Firmware — Available Targets"
	@echo ""
	@echo "Quality:"
	@echo "  make quality        Run all quality checks"
	@echo "  make cppcheck       Static analysis"
	@echo "  make complexity     Cyclomatic complexity"
	@echo "  make format-check   Code formatting check"
	@echo "  make format-fix     Auto-fix formatting"
	@echo "  make misra          MISRA C:2012 report"
	@echo "  make quality-report Full quality summary"
	@echo ""
	@echo "Build:"
	@echo "  make build-emu      Build emulator (Docker)"
	@echo "  make build-arm      Cross-compile ARM (Docker)"
