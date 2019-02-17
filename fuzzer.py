import argparse
import os
import random
import subprocess
import shlex
from contextlib import contextmanager

import generators

@contextmanager
def cd(newdir):
    prevdir = os.getcwd()
    os.chdir(os.path.expanduser(newdir))
    try:
        yield
    finally:
        os.chdir(prevdir)


def generate_input(variables, clauses, malformed):
    input = generators.dimacs_header(variables, clauses, malformed)
    input = input + '\n'
    for i in range(0, clauses):
        input = input + generators.dimacs_clause(variables, random.randint(1, variables), True)
        input = input + '\n'
    return input


parser = argparse.ArgumentParser()
parser.add_argument("sut_path", help="Absolute or Relative path to the SUT")
parser.add_argument("inputs_path", help="Absolute or Relative path to the inputs. Ignored in UB mode.")
parser.add_argument("mode", help="The mode in which the fuzzer is run. Can be either 'ub' or 'func'; all other"
                                 "values are rejected.")
parser.add_argument("seed", help="Seed for the random number generator.")
args = parser.parse_args()
print(args.sut_path)

# TODO: perform args check

with cd(args.sut_path):
    i = 1

    while i < 50:
        variables = random.randint(1, 10)
        clauses = random.randint(1, variables * 3)
        input = generate_input(variables, clauses, random.random() > 0.95)
        f = open("test.cnf", "w")
        f.write(input)
        sanitizer_output = ''
        try:
            sanitizer_output = subprocess.check_output(["./runsat.sh", "test.cnf"], shell=False)
        except subprocess.CalledProcessError as e:
            sanitizer_output = e.output
        g = open(f'san_out_{i}', "w")
        g.write(sanitizer_output.decode())
        i = i + 1
