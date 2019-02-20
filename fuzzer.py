import argparse
import os
import random
import re
import subprocess
from contextlib import contextmanager
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
    Then, generates a SolverInput instance, representing an input based on those properties.
    It then saves the input in text form in input_file, from which the SUT will read it.
    Finally, it returns the SolverInput instance, so that the fuzzer can re-use it.
    """
    variables = random.randint(1, 30)
    clauses = random.randint(1, variables * 5)
    inp = generate_input(variables, clauses, random.random() > 0.95)
    f = open(input_file, "w")
    f.write(str(inp))
    f.close()
    return inp


def get_gcov_input_counts(prev_count, curr_count):
    """
    Computes the lines in the SUT source code covered by the last fuzzer input run.
    Each source file in the SUT is represented by an array, where each element represents a line in the
    gcov report for the source file, and its value is the number of times the line was called during the run.
    It does so by comparing the gcov counts from the current iteration (i.e. after the last input) and those from
    the previous iteration (i.e. before the last input).
    :param prev_count: gcov counts before the last run input
    :param curr_count: gcov counts after the last run input
    :return: a map from source file names to the arrays described above
    """
    gcov_bitvectors = {}
    for file in prev_count.keys():
        # Arrays for the same file should have same length.
        length = len(prev_count[file])
        assert length == len(curr_count[file])
        gcov_bitvectors[file] = [curr_count[file][i] - prev_count[file][i] for i in range(0, length)]
    return gcov_bitvectors


def get_gcov_counts(source_file_names):
    """
    Parses the gcov reports for a set of source files, and for each source file, computes an array, where each element
    represents a line in the gcov report for the file, and its value is the total number of times the line has been
    called during execution.
    :param source_file_names: a list of the source file names.
    :return: a map from source file names to the arrays described above
    """
    gcov_counts = {}
    for file_name in source_file_names:
        f = open(file_name, "r")
        iterations = []
        for line in f.read().splitlines():
            # Extracts counts
            line = line.strip().split()[0][:-1]
            if line.isdigit():
                # Then line has been hit
                iterations.append(int(line))
            else:
                # Then line hasn't been hit, or does not contain code (e.g. lines with only curly braces)
                iterations.append(0)
        gcov_counts[file_name] = iterations
    print(gcov_counts)
    return gcov_counts


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
input_filename = "test.cnf"

while i < 5000:
    # Generate fuzzed input
    create_fuzzing_input(input_filename)

    # Runs a script, which calls runsat.sh on the SUT with fuzzed input,
    # then writes the sanitizer and gcov output to files
    try:
        subprocess.run(f'./run_and_get_coverage.sh {args.sut_path} 0', timeout=10, shell=True)
        # Done with files, so I can close them
        g = open('gcov_output.txt', 'r')
        gcov_filenames = g.read().split()
        get_gcov_counts(gcov_filenames)
        g.close()
    except subprocess.TimeoutExpired as e:
        print("TIMEOUT OCCURRED!")

    i = i + 1

# After last fuzzer iteration, remove test.cnf.
os.remove(input_filename)

