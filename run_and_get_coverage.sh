#!/usr/bin/env bash
# Script that runs the SUT with a fuzzed input, and generates coverage and sanitizer outputs for the fuzzer to inspect.

# First argument is SUT directory.
SUT_DIR=$1

# Second argument is whether to run the SUT; it can be 0 or 1.
# If it 0, the script will run the SUT; if it is 1, the script will simply produce the coverage metrics.
RUN_SUT=$2

# Cleanup of previous iteration; TODO: implement timeout INSIDE the bash script so that I don't do this anymore
if ${RUN_SUT}==0
then
    rm san_output.txt
fi
rm gcov_output.txt

# Move to the SUT directory
FUZZER_DIR=$(pwd)
cd ${SUT_DIR}

if ${RUN_SUT}==0
then
    # Run the SUT
    cp ${FUZZER_DIR}/test.cnf test.cnf
    ./runsat.sh test.cnf &> san_output.txt
    rm test.cnf
fi

C_FILES=$(find -name "*.c")
for filename in ${C_FILES}
do
    gcov ${filename} # produces filename.gcov file
    GCOVNAME="${filename}.gcov"
    echo "${GCOVNAME} " >> gcov_output.txt
    cp ${GCOVNAME} ${FUZZER_DIR}/${GCOVNAME}
done

# Move files back to fuzzer for analysis, perform cleanup
if ${RUN_SUT}==0
then
    cp san_output.txt ${FUZZER_DIR}/san_output.txt
    rm san_output.txt
fi
cp gcov_output.txt ${FUZZER_DIR}/gcov_output.txt
rm gcov_output.txt

cd ${FUZZER_DIR}
exit