import random
import string


class SolverInput:
    """
    Wrapper class for a DIMACS format input.

    It allows us to :
     - store a programmatic version of a SAT solver input
     - ocnvert an input to text form
     - generate randomized inputs, according to parameters which we set such as
       number of variables, number of clauses, format etc.
     - combine inputs into a larger input in order to try and maximize coverage
     - perform various kinds of metamorphic transformations on inputs.#
    This class is treated as immutable; none of its internal members are changed after creation.
    """

    def __init__(self, variables, no_of_clauses):
        self.variables = variables
        self.no_of_clauses = no_of_clauses
        self.malformed = False
        self.clauses = []
        self.generate_input()

    def generate_input(self):
        self.clauses = [self.generate_clause(random.randint(1, self.variables))
                        for _ in range(0, self.no_of_clauses)]

    def generate_clause(self, clause_length, redundant=False):
        # If not redundant, clause length must be at most
        # the number of variables for the code to work.
        if not redundant:
            assert(clause_length <= self.variables)
        available = list(range(-self.variables, 0)) + list(range(1, self.variables + 1))
        clause = []
        for i in range(0, clause_length):
            next = available[random.randint(0, len(available) - 1)]
            # If we want the clause to be non-redundant (i.e no A & ¬A, or A & A type expressions),
            # we remove the variable and its negation from the pool of choices.
            if not redundant:
                available.remove(next)
                available.remove(-next)
            clause.append(next)
        return clause

    @staticmethod
    def combine(input_1, input_2):
        combined_input = SolverInput(
            max(input_1.variables, input_2.variables),
            input_1.clauses + input_2.clauses)
        combined_input.clauses = input_1.clauses + input_2.clauses
        return combined_input

    '''
    Returns the DIMACS header, or a malformed header, depending on the boolean parameter 'malformed'.
    '''
    def dimacs_header(self):
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
        print('\n\n\n' + string_form + '\n\n\n')
        return string_form

    def __hash__(self):
        return hash(self.__str__())

