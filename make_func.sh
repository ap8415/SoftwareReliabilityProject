#!/usr/bin/env bash
# Runs make in func mode for the SUT.

# Only arg is SUT path.
SUT_PATH=$1
FUZZER_PATH=$(pwd)

cd ${SUT_PATH}
make func
cd ${FUZZER_PATH}
exit
