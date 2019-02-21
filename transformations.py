import random
import numpy.random as nprand
import generators
import input


def combine_union(input_1, input_2):
    """
    Straight union of two inputs.
    :type input_1: SolverInput
    :type input_2: SolverInput
    @return: A new input, which has a number of variables equal to the max of the two inputs' number of variables,
    and whose clauses are the concatenation of the two inputs' clauses.
    """
    new_clauses = [list(clause) for clause in input_1.get_clauses()] + \
                             [list(clause) for clause in input_2.get_clauses()]
    return input.SolverInput(max(input_1.get_variables(), input_2.get_variables()), new_clauses)


def combine_disjoint(input_1, input_2):
    """
    Disjoint union of two inputs.
    Its clauses are obtained by changing the clauses of the second input to refer to a different set of variables
    than the first, then appending them to the clauses of the first input.
    The number of variables of the new input is the sum of the number of variables in the two inputs.
    Example: if input1 has 3 variables and 1 clause, (-3 -1 -2), and input2 has 2 variables and 2 clauses, (1) and (-2),
    the combined input would have 5 variables and 3 clauses: (-3 -1 -2) & (4) & (-5).
    :type input_1: SolverInput
    :type input_2: SolverInput
    :return: the disjoint combined input.
    """
    first_input_variables = input_1.get_variables()
    second_input_variables = input_2.get_variables()
    first_input_clauses = [list(clause) for clause in input_1.get_clauses()]
    new_second_input_clauses = []
    for clause in input_2.get_clauses():
        clause = [(var + first_input_variables if var > 0 else var - first_input_variables) for var in clause]
        new_second_input_clauses.append(clause)
    return input.SolverInput(first_input_variables + second_input_variables,
                             first_input_clauses + new_second_input_clauses)


def add_random_clauses(initial_input, no_of_new_clauses):
    """
    Adds clauses to an input.
    :type initial_input: SolverInput
    :param initial_input: the initial input
    :param no_of_new_clauses: how many new clauses to add
    :return: a new input, with the same clauses as the initial one plus several random new clauses.
    SAT->UNKNOWN, UNSAT->UNSAT.
    """
    clauses = initial_input.get_clauses()
    variables = initial_input.get_variables()
    new_clauses = [list(clause) for clause in clauses]
    for _ in range(0, no_of_new_clauses):
        new_clauses.append(generators.generate_clause(variables, random.randint(1, variables)))
    return input.SolverInput(variables, new_clauses), {"SAT": "UNKNOWN", "UNSAT": "UNSAT", "UNKNOWN": "UNKNOWN"}


def permute_literals(initial_input):
    """
    Permutes the order of literals in an input.
    :type initial_input: SolverInput
    :param initial_input: the initial input
    :return: an input that is logically equivalent to the given one, with the order of the clauses permuted.
    SAT->SAT, UNSAT->UNSAT.
    """
    clauses = initial_input.get_clauses()
    variables = initial_input.get_variables()
    new_clauses = []
    for clause in clauses:
        new_clause = random.shuffle(list(clause))
        new_clauses.append(new_clause)
    return input.SolverInput(variables, new_clauses), {"SAT": "SAT", "UNSAT": "UNSAT", "UNKNOWN": "UNKNOWN"}


def add_negated_clauses(initial_input):
    """
    Takes several random clause C in the input, and returns a new input with the same clauses as the old one,
    to which the negation of C is added.
    :type initial_input: SolverInput
    :param initial_input: the initial input
    :return: A new input that has two clauses, C and ¬C.
    SAT->UNSAT, UNSAT->UNSAT.
    """
    clauses = initial_input.get_clauses()
    variables = initial_input.get_variables()
    new_clauses = [list(clause) for clause in clauses]
    for _ in random.randint(1, 10):
        negated_clause = negate_clause(clauses[random.randint(0, len(clauses) - 1)])
        new_clauses.append(negated_clause)
    return input.SolverInput(variables, new_clauses), {"SAT": "UNSAT", "UNSAT": "UNSAT", "UNKNOWN": "UNKNOWN"}


def negate_clause(clause):
    return [-var for var in clause]


def disjunct_with_new_variables(initial_input, no_of_variables):
    """
    Creates a new input, whose clauses are those of initial_input, to which disjunctions with no_of_variables new
    variables are added. To each clause, a random number of disjunctions (between 1 and no_of_variables) are added.
    These variables are chosen to be the next possible no_of_variables variables not in the input.
    Furthermore, for us to be able to pre-determine satisfiability of the new input, each variable x is only introduced
    to the input either as x or as ¬x (i.e. we will never add 4 to some clause, and -4 to another), at random.
    :return: A new input, with the new variables added to each clause.
    SAT->SAT, UNSAT->UNSAT
    """
    clauses = initial_input.get_clauses()
    variables = initial_input.get_variables()
    new_clauses = []
    new_terms = [(var if random.random() > 0.5 else -var) for var in range(variables + 1, variables + no_of_variables)]
    for clause in clauses:
        new_clause = list(clause) + nprand.choice(new_terms, random.randint(1, no_of_variables), replace=False)
        new_clauses.append(new_clause)
    return input.SolverInput(variables, new_clauses), {"SAT": "SAT", "UNSAT": "UNSAT", "UNKNOWN": "UNKNOWN"}
