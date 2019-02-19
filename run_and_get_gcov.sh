#!/usr/bin/env bash
SUT_DIR = $1
SUT_DIR/runsat.sh test.cnf &> san_output.txt
find -name "$SUT_DIR/*.c" -exec gcov {} \; > gcov_output.txt
exit
