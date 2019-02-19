!/bin/bash 

           ./runsat.sh test.cnf &> san_output.txt 

           find -name '*.c' -exec gcov {} \; > gcov_output.txt