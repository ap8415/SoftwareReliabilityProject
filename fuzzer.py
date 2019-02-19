import argparse
import os
import random
import re
import subprocess
from contextlib import contextmanager
import generators
from input import SolverInput

@contextmanager
def cd(newdir):
    prevdir = os.getcwd()
    os.chdir(os.path.expanduser(newdir))
    try:
        yield
    finally:
        os.chdir(prevdir)


def generate_input(variables, clauses, malformed):
    return SolverInput(variables, clauses)


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
gcov_coverage_percent_regex = re.compile(r"\d{1,3}\.\d{0,2}%")


def parse_gcov_info(gcov_output):
    """
    Parses the gcov output to a mapping, giving the coverage of each of the SUT files.
    :param gcov_output: the output produced by gcov by some SUT for some input
    :return: a (file name, coverage) mapping
    """
    output_per_file = gcov_main_regex.finditer(gcov_output)
    file_coverage = {}
    for file_info in output_per_file:
        print(file_info.group())
        # Get filename via regex, remove the (redundant) leading ' and trailing .c'
        filename = gcov_sourcefile_regex.search(file_info.group()).group()[1:-3]
        print(f'FILENAME IS {filename}')
        percent_coverage = gcov_coverage_percent_regex.search(file_info.group()).group()
        print(f'COVERAGE IS {percent_coverage}')
        percent_coverage = float(percent_coverage[:-1])
        file_coverage[filename] = percent_coverage
    return file_coverage


input_filename = "test.cnf"

while i < 50:
    # Generate fuzzed input
    create_fuzzing_input(input_filename)

    # Runs a script, which calls runsat.sh on the SUT with fuzzed input,
    # then writes the sanitizer and gcov output to files
    subprocess.run(f'./run_and_get_gcov.sh {args.sut_path}', shell=True)

    # Done with files, so I can close them
    g = open('gcov_output.txt', 'r')
    parsed_gcov_info = parse_gcov_info(g.read())
    g.close()
    print(parsed_gcov_info)

    i = i + 1

# After last fuzzer iteration, remove test.cnf.
os.remove(input_filename)

