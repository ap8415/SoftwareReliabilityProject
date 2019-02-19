import argparse
import os
import random
import re
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


def create_fuzzing_input(input_file):
    """
    Randomly generates all the properties of the fuzzed input(no. of variables, clauses etc).
    Then, generates an input based on those properties.
    Finally, it saves the input in input_file, from which the SUT will read it.
    TODO: perhaps return the randomly generated parameters, so that they can be used in an analysis.
    """
    variables = random.randint(1, 10)
    clauses = random.randint(1, variables * 3)
    input = generate_input(variables, clauses, random.random() > 0.95)
    f = open(input_file, "w")
    f.write(input)
    f.close()


parser = argparse.ArgumentParser()
parser.add_argument("sut_path", help="Absolute or Relative path to the SUT")
parser.add_argument("inputs_path", help="Absolute or Relative path to the inputs. Ignored in UB mode.")
parser.add_argument("mode", help="The mode in which the fuzzer is run. Can be either 'ub' or 'func'; all other"
                                 "values are rejected.")
parser.add_argument("seed", help="Seed for the random number generator.")
args = parser.parse_args()
print(args.sut_path)

# TODO: perform args check
# TODO: verify that this works with both absolute and relative paths.

i = 1
# Regexes used to parse gcov
gcov_main_regex = re.compile(r"file '\w+\.c'\nlines executed:\d{1,3}\.\d{0,2}% of \d+", re.I)
gcov_sourcefile_regex = re.compile(r"'\w+\.c'")
gcov_coverage_percent_regex = re.compile(r"\d{1,3}%\d{0,2}")


def parse_gcov_info(gcov_output):
    """
    Parses the gcov output to a mapping, giving the coverage of each of the SUT files.
    :param gcov_output: the output produced by gcov by some SUT for some input
    :return: a (file name, coverage) mapping
    """
    output_per_file = gcov_main_regex.finditer(gcov_output)
    file_coverage = {}
    for file_info in output_per_file:
        # Get filename via regex, remove the (redundant) leading ' and trailing .c'
        filename = gcov_sourcefile_regex.match(file_info.group()).group()[1:-3]
        percent_coverage = gcov_coverage_percent_regex.match(file_info.group())
        percent_coverage = float(percent_coverage[:-1])
        file_coverage[filename] = percent_coverage
    return file_coverage


with cd(args.sut_path):
    while i < 50:
        # Generate fuzzed input
        input_filename = "test.cnf"
        create_fuzzing_input(input_filename)

        # Run the SUT with fuzzed input, writing the output and the sanitizer error messages to a file
        g = open('san_output', "w")
        subprocess.run(['runsat.sh', input_filename], stdout=g, stderr=g)

        # Obtain gcov info for the given file
        h = open('gcov_info', "w+")
        subprocess.run(['gcov', '*.c'], stdout=h)

        # Obtain line coverage for all of the files
        sut_coverage = parse_gcov_info(h.read())

        # Done with files, so I can close them
        g.close()
        h.close()

        i = i + 1

    # After last fuzzer iteration, remove test.cnf.
    os.remove("test.cnf")

