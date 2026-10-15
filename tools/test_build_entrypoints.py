"""Build interfaces preserve native declarations and caller argument boundaries."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class BuildEntrypoints(unittest.TestCase):
    def test_string_prototypes_match_supported_libcs(self):
        header = ROOT / "include/keepkey/board/bsd_compat.h"
        source = ("#include <string.h>\n"
                  "size_t probe(char* d, const char* s, size_t n) {\n"
                  "  return strlcpy(d, s, n) + strlcat(d, s, n);\n}\n")
        # Model both native signatures and both missing-prototype cases, then
        # compile against the runner's actual headers as well. This catches
        # conflicts in either include order, without needing four machines.
        for libc in ["glibc-new", "glibc-old", "musl", "mingw", "native"]:
            with tempfile.TemporaryDirectory() as tmp:
                include = []
                if libc != "native":
                    contents = "#pragma once\n#undef __GLIBC__\n"
                    if libc.startswith("glibc"):
                        contents += "#define __GLIBC__ 2\n"
                    if libc in ["glibc-new", "musl"]:
                        exception = "noexcept" if libc == "glibc-new" else ""
                        contents += ('#ifdef __cplusplus\nextern "C" {\n'
                                     '#define TEST_EXCEPT ' + exception + '\n'
                                     '#else\n#define TEST_EXCEPT\n#endif\n'
                                     'size_t strlcpy(char*, const char*, size_t) TEST_EXCEPT;\n'
                                     'size_t strlcat(char*, const char*, size_t) TEST_EXCEPT;\n'
                                     '#ifdef __cplusplus\n}\n#endif\n')
                    (Path(tmp) / "string.h").write_text(contents)
                    include = ["-I", tmp]
                for compiler, language, standard in [
                    ("cc", "c", "c99"), ("c++", "c++", "c++11")
                ]:
                    with self.subTest(libc=libc, language=language):
                        result = subprocess.run([compiler, "-x", language, "-std=" + standard,
                                        "-Werror", "-fsyntax-only", *include,
                                        "-include", str(header), "-"], input=source,
                                       text=True, capture_output=True)
                        self.assertEqual(result.returncode, 0, result.stderr)

    def test_release_script_preserves_cmake_arguments(self):
        with tempfile.TemporaryDirectory(prefix="keepkey-build-") as tmp:
            root = Path(tmp)
            script = root / "source with spaces/scripts/build/docker/device/release.sh"
            script.parent.mkdir(parents=True)
            shutil.copy2(ROOT / "scripts/build/docker/device/release.sh", script)
            bindir = root / "test-bin"
            bindir.mkdir()
            # Execute the actual container shell command with harmless stand-ins
            # for build tools. CMake records the argv it actually receives.
            docker = bindir / "docker"
            docker.write_text(
                "#!/usr/bin/env python3\nimport os, subprocess, sys\n"
                "if sys.argv[1:3] == ['image', 'inspect']: sys.exit(0)\n"
                "i = sys.argv.index('/bin/sh')\n"
                "sys.exit(subprocess.call(sys.argv[i:]))\n")
            docker.chmod(0o755)
            for name in ["mkdir", "make", "cp", "chown"]:
                p = bindir / name
                p.write_text("#!/bin/sh\nexit 0\n")
                p.chmod(0o755)
            (bindir / "stat").write_text("#!/bin/sh\nprintf '1:1'\n")
            (bindir / "stat").chmod(0o755)
            # The shell's cd needs an existing directory; rewrite only the
            # container build directory to a temporary local directory.
            build = root / "build"
            build.mkdir()
            script.write_text(script.read_text().replace("/root/build", str(build)))
            cmake = bindir / "cmake"
            cmake.write_text("#!/usr/bin/env python3\nimport json, os, sys\n"
                             "open(os.environ['KEEPKEY_ARGV_RECORD'], 'w').write("
                             "json.dumps(sys.argv[1:]))\n")
            cmake.chmod(0o755)
            record = root / "argv.json"
            env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ["PATH"],
                       KEEPKEY_ARGV_RECORD=str(record), KEEPKEY_TEST_LITERAL="not-expanded")
            extra = ["-DCMAKE_C_FLAGS=-DFOO=1 -DBAR=1",
                     "-DVALUE=literal;$KEEPKEY_TEST_LITERAL", "-DEMPTY="]
            result = subprocess.run(["bash", str(script), *extra], env=env,
                           capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(extra, json.loads(record.read_text())[-len(extra):])


if __name__ == "__main__":
    unittest.main()
