import random
import string

import generators


class SolverInput:
    """
    Wrapper class for a DIMACS format input.

    It allows us to :
     - store a programmatic version of a SAT solver input
     - convert an input to text form
     - generate randomized inputs, according to parameters which we set such as number of variables,
     number of clauses, format etc.
     - combine inputs into a larger input in order to try and maximize coverage
     - perform various kinds of metamorphic transformations on inputs.
    This class is treated as immutable; none of its internal members are changed after creation.
    """

    def __init__(self, variables, clauses):
        self.variables = variables
        self.malformed = False
        self.clauses = clauses
        self.no_of_clauses = len(clauses)

    def get_clauses(self):
        return self.clauses

    def get_variables(self):
        return self.variables

    def dimacs_header(self):
        """
        Returns the DIMACS header, or a malformed header, depending on the boolean parameter 'malformed'.
        """
        if not self.malformed:
            return f'p cnf {self.variables} {self.no_of_clauses}'
        else:
            # Try random malformations, or just random string
            if random.random() > 0.2:
                return f'q cnf {self.variables} {self.no_of_clauses}'
            elif random.random() > 0.3:
                return f'p dnf {self.variables} {self.no_of_clauses}'
            elif random.random() > 0.2:
                return f'{self.variables} {self.no_of_clauses} p cnf'
            elif random.random() > 0.2:
                return f'p p cnf {self.variables} {self.no_of_clauses}'
            else:
                return ''.join(random.choices(string.ascii_uppercase + string.digits, k=random.randint(0, 20)))

    def __str__(self):
        # First append header
        string_form = self.dimacs_header() + '\n'
        for clause in self.clauses:
            # TODO :add static method, clause(list of ints) -> string
            for item in clause:
                string_form = string_form + f'{item} '
            string_form = string_form + '0\n'
        return string_form

    def __hash__(self):
        return hash(self.__str__())

    def should_run_fast(self):
        """
        Simple heuristic to estimate whether the input is small enough to be runnable fast.
        """
        return sum([len(clause) for clause in self.clauses]) < 50000 or len(self.clauses) < 5000


    @staticmethod
    def create_input(variables, no_of_clauses):
        """
        Factory method to generate a new random input.
        :param variables: number of variables
        :param no_of_clauses: number of clauses
        :return: a new random input
        """
        print(f'{variables} AND {no_of_clauses}')
        return SolverInput(variables, SolverInput.generate_clauses(variables, no_of_clauses))

    @staticmethod
    def generate_clauses(variables, no_of_clauses):
        return [generators.generate_clause(variables, random.randint(1, variables))
                for _ in range(0, no_of_clauses)]
