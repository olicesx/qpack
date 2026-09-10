#!/bin/bash
set -euo pipefail

export CXX="${CXX:-} -lresolv" # required by Go 1.20

compile_go_fuzzer github.com/olicesx/qpack/fuzzing Fuzz qpack_fuzzer
