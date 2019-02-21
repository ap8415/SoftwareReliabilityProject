import argparse
import os
import random
import re
import subprocess
import time
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
    return SolverInput.create_input(variables, clauses)


def create_fuzzing_input(input_file):
    """
    Randomly generates all the properties of the fuzzed input(no. of variables, clauses etc).
    Then, generates a SolverInput instance, representing an input based on those properties.
    It then saves the input in text form in input_file, from which the SUT will read it.
    Finally, it returns the SolverInput instance, so that the fuzzer can re-use it.
    """
    variables = random.randint(10, 100)
    clauses = random.randint(variables, variables * 3)
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
    return gcov_counts


# Initialize globals

# A list of tuples, which pairs each input with its coverage metrics.
tracked_inputs = []
interesting_inputs = []

regex_heap_buf_overflow = re.compile(r'ERROR: AddressSanitizer: heap-buffer-overflow on address')
regex_heap_use_after_free = re.compile(r'ERROR: AddressSanitizer: heap-use-after-free on address')
regex_stack_buf_overflow = re.compile(r'ERROR: AddressSanitizer: stack-buffer-overflow on address')
regex_global_buf_overflow = re.compile(r'ERROR: AddressSanitizer: global-buffer-overflow on address')
regex_stack_use_after_return = re.compile(r'ERROR: AddressSanitizer: stack-use-after-return on address')
regex_initializer_order_err = re.compile(r'ERROR: AddressSanitizer: initialization-order-fiasco on address')
regex_use_after_scope_err = re.compile(r'ERROR: AddressSanitizer: stack-use-after-scope on address')
asan_errors = [regex_heap_buf_overflow,
               regex_heap_use_after_free,
               regex_stack_buf_overflow,
               regex_global_buf_overflow,
               regex_stack_use_after_return,
               regex_initializer_order_err,
               regex_use_after_scope_err]


def examine_sanitizer_output():
    f = open('san_output.txt', 'r')
    sanout = f.read()

    regex_undef_behaviour = re.compile(r'[\w :]+runtime error: [\w -]+\n')
    undef_behaviours = regex_undef_behaviour.finditer(sanout)
    for undef_behaviour_instance in undef_behaviours:
        print(f'Undefined behaviour detected: {undef_behaviour_instance.group()}')

    for asan_error in asan_errors:
        asan_errors_detected = asan_error.finditer(sanout)
        for err in asan_errors_detected:
            print(f'Undefined behaviour detected: {err.group()}')


def fuzz():
    """
    Main fuzzing method.
    Generates an input, then obtains its coverage and sanitizer outputs.
    For sanitizer outputs, the method classifies the discovered bug, and compares it to the previously found bugs,
    with the aim of finding diverse and severe flaws.
    For coverage outputs, the method
    """
    global curr_gcov_counts
    global prev_gcov_counts
    global tracked_inputs
    global initial
    # Generate fuzzed input
    curr_input = create_fuzzing_input(input_filename)

    print(time.clock() - initial)
    # Runs a script, which calls runsat.sh on the SUT with fuzzed input,
    # then writes the sanitizer and gcov output to files
    try:
        subprocess.run(f'./run_and_get_coverage.sh {args.sut_path} 0', timeout=30, shell=True)
        # Done with files, so I can close them
        g = open('gcov_output.txt', 'r')
        curr_gcov_counts = get_gcov_counts(g.read().split())
        g.close()

        gcov_input_counts = get_gcov_input_counts(prev_gcov_counts, curr_gcov_counts)
        prev_gcov_counts = curr_gcov_counts
        tracked_inputs.append((curr_input, gcov_input_counts))

        examine_sanitizer_output()
    except subprocess.TimeoutExpired:
        print("TIMEOUT OCCURRED!")


def augment():
    """
    Inspects the current pool of inputs, and saves them to interesting_inputs.
    If interesting_inputs becomes too big, the method also evicts the oldest inputs.
    """
    global interesting_inputs
    global curr_gcov_counts
    global tracked_inputs
    next_interesting_inputs = set()

    # Determine largest line count for every file.
    # We disregard lines which have more than 1% of the maximum count, as they are reachable enough by regular
    # fuzzed tests.
    max_counts = {}
    for file in curr_gcov_counts.keys():
        max_counts[file] = max(curr_gcov_counts[file])

    for file in curr_gcov_counts.keys():
        for i in range(0, len(curr_gcov_counts[file])):
            if curr_gcov_counts[file][i] < 0.01 * max_counts[file]:
                max_count = 0
                best_input = None
                for input, counts in tracked_inputs:
                    if counts[file][i] > max_count:
                        max_count = counts[file][i]
                        best_input = input
                if best_input is not None:
                    next_interesting_inputs.add(best_input)

    interesting_inputs = interesting_inputs + list(next_interesting_inputs)
    tracked_inputs = []
    if len(interesting_inputs) > 200:
        interesting_inputs = interesting_inputs[-200:]
    print(len(interesting_inputs))
    

# Parse args

parser = argparse.ArgumentParser()
parser.add_argument("sut_path", help="Absolute or Relative path to the SUT")
parser.add_argument("inputs_path", help="Absolute or Relative path to the inputs. Ignored in UB mode.")
parser.add_argument("mode", help="The mode in which the fuzzer is run. Can be either 'ub' or 'func'; all other"
                                 "values are rejected.")
parser.add_argument("seed", help="Seed for the random number generator.")
args = parser.parse_args()
# TODO: perform args check
# TODO: verify that this works with both absolute and relative paths.

input_filename = "test.cnf"
# If test.cnf is already present, clean it up first.
# TODO

# Get initial zero values for coverage so that we can compute rolling coverage for each test input
subprocess.run(f'./run_and_get_coverage.sh {args.sut_path} 1', timeout=10, shell=True)
g = open('gcov_output.txt', 'r')
gcov_filenames = g.read().split()
prev_gcov_counts = get_gcov_counts(gcov_filenames)
curr_gcov_counts = {}
g.close()

initial = time.clock()

# Run the fuzzing process.
# We iterate a limited number of times, then augment the pool of interesting inputs.
# 200 is an appropriate number here, enough to let a decent collection of inputs accummulate
# while keeping the memory footprint relatively low.
for i in range(0, 3000):
    fuzz()
    print(i)
# Augment interesting inputs pool.
# augment()

print(time.clock() - initial)
