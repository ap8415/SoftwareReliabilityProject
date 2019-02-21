import argparse
import os
import random
import re
import subprocess
import time

import transformations
from modes import *
from collections import deque
from contextlib import contextmanager
from input import SolverInput
import numpy.random as nprand


def generate_input(variables, clause_params, malformed):
    return SolverInput.create_input(variables, clause_params)


def create_ub_fuzzing_input():
    """
    Randomly generates all the properties of the fuzzed input(no. of variables, clauses etc).
    Then, generates a SolverInput instance, representing an input based on those properties.
    It then saves the input in text form in input_file, from which the SUT will read it.
    Finally, it returns the SolverInput instance, so that the fuzzer can re-use it.
    """
    global mode_variables
    global mode_clauses

    variables = mode_variables.get_variables()
    clause_params = mode_clauses.get_clause_parameters()

    inp = generate_input(variables, clause_params, random.random() > 0.99)
    write_input_to_file(inp)

    return inp


def write_input_to_file(input):
    """
    Writes an input to the test.cnf file.
    """
    input_filename = "test.cnf"
    f = open(input_filename, "w")
    f.write(str(input))
    f.close()


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


# ASan parsing
regex_heap_buf_overflow = re.compile(r'ERROR: AddressSanitizer: heap-buffer-overflow on address[\w ]+\n.+\n]')
regex_heap_use_after_free = re.compile(r'ERROR: AddressSanitizer: heap-use-after-free on address[\w ]+\n.+\n]')
regex_stack_buf_overflow = re.compile(r'ERROR: AddressSanitizer: stack-buffer-overflow on address[\w ]+\n.+\n]')
regex_global_buf_overflow = re.compile(r'ERROR: AddressSanitizer: global-buffer-overflow on address[\w ]+\n.+\n]')
regex_stack_use_after_return = re.compile(r'ERROR: AddressSanitizer: stack-use-after-return on address[\w ]+\n.+\n]')
regex_initializer_order_err = re.compile(r'ERROR: AddressSanitizer: initialization-order-fiasco on address[\w ]+\n.+\n]')
regex_use_after_scope_err = re.compile(r'ERROR: AddressSanitizer: stack-use-after-scope on address[\w ]+\n.+\n]')
asan_errors = {"heap_buf_overflow": regex_heap_buf_overflow,
               "heap_use_after_free": regex_heap_use_after_free,
               "stack_buf_overflow": regex_stack_buf_overflow,
               "global_buf_overflow": regex_global_buf_overflow,
               "use_after_return": regex_stack_use_after_return,
               "initialization_order": regex_initializer_order_err,
               "use_after_scope": regex_use_after_scope_err}

# UBSan parsing
regex_detect_undef_behaviour = re.compile(r'[\w. :]+runtime error: [\w -]+\n')
regex_parse_undef_behaviour = re.compile(r'runtime error: [\w -]+\n')


def classify_undefined_behaviours():
    """
    Parses the sanitizer output to detect undefined behaviours found in the test cases.
    :return: a list of pairs, which consist of undefined behaviour + code location
    """
    f = open('san_output.txt', 'r')
    san_out = f.read()

    undefined_behaviours = []

    detected_undef_behaviours = regex_detect_undef_behaviour.finditer(san_out)
    for undef_behaviour_instance in detected_undef_behaviours:
        ubsan_error = undef_behaviour_instance.group()
        code_location = ubsan_error.split()[0][:-1]
        error_msg = regex_parse_undef_behaviour.search(ubsan_error).group()[15:-1]
        print(f'Undefined behaviour detected: {error_msg} ; at {code_location}')
        undefined_behaviours.append((error_msg, code_location))

    for asan_error in asan_errors.keys():
        asan_errors_detected = asan_errors[asan_error].finditer(san_out)
        for err in asan_errors_detected:
            code_location = err.group().split()[-1]
            print(f'Undefined behaviour detected: {asan_error} at {code_location}')
            undefined_behaviours.append((asan_error, code_location))

    return undefined_behaviours


# Initialize globals

# A list of tuples, which pairs each input with its coverage metrics.
interesting_inputs = deque()

# Stores the list of undefined behaviours which have been saved by the fuzzer.
undef_behaviour_list = []

# Stores how many inputs have been produced since an interesting input was detected
since_last_interesting_input = 0

mode_variables = None
mode_clauses = None
possible_modes_variables = [v for v in ModeVariables]
possible_modes_clauses = [c for c in ModeClauses]


def select_random_modes():
    """
    Randomizes the generation modes for the fuzzer.
    """
    global mode_variables
    global mode_clauses

    mode_variables = nprand.choice(possible_modes_variables, p=[0.15, 0.34, 0.4, 0.1, 0.0095, 0.0005])
    mode_clauses = nprand.choice(possible_modes_clauses, p=[0.3, 0.3, 0.3, 0.09, 0.01])


def fuzz_ub():
    """
    Main fuzzing method.
    Generates an input, then obtains its coverage and sanitizer outputs.
    For sanitizer outputs, the method classifies the discovered bug, and compares it to the previously found bugs,
    with the aim of finding diverse and severe flaws.
    For coverage outputs, the method observes which lines of code were executed by the input, and detects if any lines
    have not been previously executed. If that is the case, the input is classified as 'interesting', and reused.
    """
    global curr_gcov_counts
    global prev_gcov_counts
    global initial
    global undef_behaviour_list

    # Generate fuzzed input
    curr_input = create_ub_fuzzing_input()

    print(time.clock() - initial)

    # Runs a script, which calls runsat.sh on the SUT with fuzzed input,
    # then writes the sanitizer and gcov output to files
    fuzz_the_sut = subprocess.run(f'./run_and_get_coverage.sh {args.sut_path} 0 30', shell=True)
    try:
        # If the SUT didn't time out out, the script will return 0, and we can process the information
        fuzz_the_sut.check_returncode()

        # Process coverage information
        g = open('gcov_output.txt', 'r')
        curr_gcov_counts = get_gcov_counts(g.read().split())
        prev_gcov_counts = curr_gcov_counts
        g.close()

        augment(curr_input)

        # Process sanitizer information
        curr_behaviours = classify_undefined_behaviours()
        # If no undefined behaviour has been found, return
        if not curr_behaviours:
            return

        seen_before = False
        for beh in undef_behaviour_list:
            if beh == curr_behaviours:
                seen_before = True
        if not seen_before:
            undef_behaviour_list.append(curr_behaviours)

    except subprocess.CalledProcessError:
        # If the SUT timed out, the script will return 1, and an exception is raised by subprocess.
        print("TIMEOUT OCCURRED!")


def augment(input):
    """
    Inspects the given input's coverage, and if it is interesting, saves it to interesting_inputs.
    If interesting_inputs becomes too big, the method also evicts the oldest inputs.
    """
    global interesting_inputs
    global since_last_interesting_input

    if check_for_interesting_input():
        interesting_inputs.append(input)
        since_last_interesting_input = 0
    else:
        since_last_interesting_input = since_last_interesting_input + 1

    if len(interesting_inputs) > 200:
        interesting_inputs.popleft()  # Remove the oldest input


def check_for_interesting_input():
    """
    Checks whether the current input reached a new line of code in the SUT.
    """
    global curr_gcov_counts
    global prev_gcov_counts

    for file in curr_gcov_counts.keys():
        for i in range(0, len(curr_gcov_counts[file])):
            if prev_gcov_counts[file][i] == 0 and curr_gcov_counts[file][i] > 0:
                return True

    return False


# Parse args

parser = argparse.ArgumentParser()
parser.add_argument("sut_path", help="Absolute or Relative path to the SUT")
parser.add_argument("inputs_path", help="Absolute or Relative path to the inputs. Ignored in UB mode.")
parser.add_argument("mode", help="The mode in which the fuzzer is run. Can be either 'ub' or 'func'; all other"
                                 "values are disregarded.")
parser.add_argument("seed", help="Seed for the random number generator.")
args = parser.parse_args()
# TODO: perform args check
# TODO: verify that this works with both absolute and relative paths.

random.seed(int(args.seed))

# Get initial zero values for coverage so that we can compute rolling coverage for each test input
subprocess.run(f'./run_and_get_coverage.sh {args.sut_path} 1 0', shell=True)
g = open('gcov_output.txt', 'r')
gcov_filenames = g.read().split()
prev_gcov_counts = get_gcov_counts(gcov_filenames)
curr_gcov_counts = {}
g.close()

initial = time.clock()

def parse_input(file_name):
    """
    Parses the input file, and returns a SolverInput instance that matches it.
    :param file_name: the input file name
    :return: a SolverInput instance representing the input
    """
    # First parse input file, and convert it into a SolverInput instance
    f = open(file_name, 'r')
    given_input = f.read().splitlines()

    i = 0
    # Skip any comments
    while given_input[i][0] == 'c':
        i = i + 1

    variables, no_of_clauses = int(given_input[i].split()[2]), int(given_input[i].split()[3])

    text_clauses = ' '.join(given_input[i + 1:]).split()
    clauses = []
    curr = 0
    for j in range(0, no_of_clauses):
        clause = []
        while text_clauses[curr] != '0':
            clause.append(int(text_clauses[curr]))
            curr = curr + 1
        curr = curr + 1
        clauses.append(clause)

    return SolverInput(variables, clauses)


def produce_transformed_input(input, sat, transforms_left=4):
    """
    Applies up to transforms_left transformations on the given input.
    """
    if transforms_left == 0:
        return input, sat

    new_input, new_sat = apply_transform(input, sat)
    if new_input is None:
        return input, sat
    elif random.random() > 0.75:
        return produce_transformed_input(new_input, new_sat, transforms_left - 1)
    else:
        return new_input, new_sat


def apply_transform(input, sat):
    """
    Applies a metamorphic transform to the given input.
    If none of the transforms produce a non-trivial satisfiability output, returns (None, None).
    """
    transforms = random.shuffle(range(0, 5))

    # Uniformly picks a random transformation; if it doesn't produce an acceptable satisfiability output, tries to
    # move on to the next transform until it runs out of transformations.
    while transforms:
        picked_transform = transforms[0]
        transforms.remove(picked_transform)
        new_input, followup_sat = [], []
        if picked_transform == 0:
            new_input, followup_sat = \
                transformations.add_random_clauses(input, random.randint(1, len(input.get_clauses())) * 0.5)
        elif picked_transform == 1:
            new_input, followup_sat = transformations.add_negated_clauses(input)
        elif picked_transform == 2:
            new_input, followup_sat = transformations.disjunct_with_new_variables(input, random.randint(1, input.get_variables() * 0.2))
        elif picked_transform == 3:
            new_input, followup_sat = transformations.permute_literals(input)
        elif picked_transform == 4:
            new_input, followup_sat = input, sat # TODO
        combined_sat = {"SAT": followup_sat[sat["SAT"]],
                        "UNSAT": followup_sat[sat["UNSAT"]],
                        "UNKNOWN": "UNKNOWN"}
        if not combined_sat["SAT"] == "UNKNOWN" or not combined_sat["UNSAT"] == "UNKNOWN":
            return new_input, combined_sat

    return None, None
    # Choose transform at random.


def create_follow_up_tests(file_name):
    """
    Main function for func fuzzing mode.
    Generates 50 test cases for each of the inputs.
    :param file_name: the input file name
    """

    global prev_gcov_counts
    global curr_gcov_counts
    global interesting_inputs

    input = parse_input(file_name)

    if input.should_run_fast():
        # If the input is small enough, we can invoke the SUT on the follow-up tests,
        # to determine which are worth keeping.
        while len(interesting_inputs) < 50:

            # If we can't find any more interesting inputs via coverage, we abandon this approach.
            if since_last_interesting_input > 15:
                break

            new_input = produce_transformed_input(input, {"SAT": "SAT", "UNSAT": "UNSAT", "UNKNOWN": "UNKNOWN"})
            write_input_to_file(new_input)
            # Use 60-second timeout to try follow-up tests.
            fuzz_the_sut = subprocess.run(f'./run_and_get_coverage.sh {args.sut_path} 0 60', shell=True)

            try:
                # If the SUT didn't time out out, the script will return 0, and we can process the information
                fuzz_the_sut.check_returncode()

                # Process coverage information
                g = open('gcov_output.txt', 'r')
                curr_gcov_counts = get_gcov_counts(g.read().split())
                prev_gcov_counts = curr_gcov_counts
                g.close()

                augment(new_input)

            except subprocess.CalledProcessError:
                # If the test times out, given that the input is deemed small, it's most likely that
                # it found a flaw in the SUT, so we keep it.
                interesting_inputs.append(new_input)

    # If the input is deemed too big, such that running a transformed version of it in the SUT will take too long,
    # or if we can't find 'interesting' inputs anymore, we simply add transformed inputs up to the 50 limit.
    while len(interesting_inputs) < 50:
        interesting_inputs.append(produce_transformed_input(input))


if args.mode == "ub":
    # Fuzz in ub mode.
    while True:
        fuzz_ub()
        # Augment interesting inputs pool.
        print(time.clock() - initial)
elif args.mode == "func":
    # Fuzz in func mode.
    func_path = "follow-up-tests"
    os.mkdir(func_path)
    subprocess.run(f'./copy_inputs.sh {args.inputs_path}', shell=True)

    g = open('inputs.txt', 'r')
    file_names = g.read().split()

    for file_name in file_names:
        create_follow_up_tests(file_name)
        for i in range(0, 50):
            test_file = open(f'follow-up-tests/{file_name}_{i}.cnf', 'w')
            sat_file = open(f'follow-up-tests/{file_name}_{i}.txt', 'w')
            test_file.write(str(interesting_inputs[i]))
            # TODO: write SAT expectation to file
            test_file.close()
            sat_file.close()
