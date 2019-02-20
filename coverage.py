


class Coverage:
    """
    Represents a coverage report for a fuzzed input.
    For each source file in the SUT, we store a bit-vector, with number of bits equal to the number of lines in the
    gcov report for the file, marking which lines have appeared for the SUT.
    """