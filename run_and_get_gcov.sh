#!/usr/bin/env bash
# Script that runs the SUT with a fuzzed input, and generates coverage and sanitizer outputs for the fuzzer to inspect. 

# Cleanup of previous iteration
rm san_output.txt
rm gcov_output.txt

# Move to the SUT directory
SUT_DIR=$1
FUZZER_DIR=$(pwd)
cd ${SUT_DIR}
cp ${FUZZER_DIR}/test.cnf test.cnf

# Run the SUT, generate coverage
./runsat.sh test.cnf &> san_output.txt
find -name "*.c" -exec gcov {} \; > gcov_output.txt

# Move files back to fuzzer for analysis, perform cleanup
cp san_output.txt ${FUZZER_DIR}/san_output.txt
cp gcov_output.txt ${FUZZER_DIR}/gcov_output.txt
rm san_output.txt
rm gcov_output.txt
rm test.cnf

cd ${FUZZER_DIR}
exit
