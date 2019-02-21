#!/usr/bin/env bash
# Copies the inputs to the fuzzer directory from the inputs directory.
# Writes a list of their names to a file in the fuzzer dir.

# First argument is inputs directory.
INPUTS_DIR=$1

FUZZER_DIR=$(pwd)

cd ${INPUTS_DIR}

for file in $(ls)
do
    cp ${file} ${FUZZER_DIR}/${file}
    echo "${file} \n" > ${FUZZER_DIR}/inputs.txt
done

cd ${FUZZER_DIR}
exit