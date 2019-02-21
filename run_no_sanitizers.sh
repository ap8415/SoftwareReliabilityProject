#!/usr/bin/env bash
#!/usr/bin/env bash
# Script that runs the SUT with a fuzzed input, and generates coverage and sanitizer outputs for the fuzzer to inspect.

# First argument is SUT directory.
SUT_DIR=$1

# Specify timeout for running the SUT, in seconds.
TIMEOUT=$2

# Cleanup of previous iteration; TODO: implement timeout INSIDE the bash script so that I don't do this anymore
if [[ "${RUN_SUT}" = "0" ]];
then
    rm san_output.txt
fi
rm gcov_output.txt

# Move to the SUT directory
FUZZER_DIR=$(pwd)
cd ${SUT_DIR}

RET_CODE=0
if [[ "${RUN_SUT}" = "0" ]];
then
    # Run the SUT
    cp ${FUZZER_DIR}/test.cnf test.cnf
    timeout ${TIMEOUT}s ./runsat.sh test.cnf &> san_output.txt
    RET_CODE=$(echo $?)
    rm test.cnf
fi

# If command times out, return 1
if ${RET_CODE} = 124
then
    rm san_output.txt
    cd ${FUZZER_DIR}
    exit 1
fi

C_FILES=$(find -name "*.c")
for filename in ${C_FILES}
do
    gcov ${filename} &> /dev/null # produces filename.gcov file
    GCOVNAME="${filename}.gcov"
    echo "${GCOVNAME} " >> gcov_output.txt
    cp ${GCOVNAME} ${FUZZER_DIR}/${GCOVNAME}
done

# Move files back to fuzzer for analysis, perform cleanup
if [[ "${RUN_SUT}" = "0" ]];
then
    cp san_output.txt ${FUZZER_DIR}/san_output.txt
    rm san_output.txt
fi
cp gcov_output.txt ${FUZZER_DIR}/gcov_output.txt
rm gcov_output.txt

cd ${FUZZER_DIR}
exit 0
