# Local Fuzzing

The parser fuzz targets are opt-in local tools. They are not built by the
default CI CMake path.

## Core Parser Targets

Build with Clang/libFuzzer:

```sh
cmake -S . -B build-fuzz -DMODERN_PKI_ENABLE_FUZZING=ON -DCMAKE_CXX_COMPILER=clang++
cmake --build build-fuzz --target modern_pki_core_csr_fuzz modern_pki_core_ocsp_fuzz modern_pki_core_crl_fuzz
```

Run short local passes:

```sh
./build-fuzz/modern_pki_core_csr_fuzz -max_total_time=60
./build-fuzz/modern_pki_core_ocsp_fuzz -max_total_time=60
./build-fuzz/modern_pki_core_crl_fuzz -max_total_time=60
```

Use longer runs and saved corpora when investigating parser crashes.
