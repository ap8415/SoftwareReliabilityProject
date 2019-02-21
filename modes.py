from enum import Enum
import random

class ModeClauses(Enum):
    """
    Describes the clauses format used by the fuzzer in ub mode.
    """
    MANY_AND_SHORT = 1,
    BALANCED = 2,
    FEW_AND_LONG = 3,
    MANY_AND_LONG = 4,
    SPECIAL = 5

    def get_clause_parameters(self, variables):
        # Note: I generate at most 1000k literals, as the generation and solving is way too slow if I exceed this limit
        # and we run into timeout for no reason.
        if self is ModeClauses.MANY_AND_SHORT:
            # Limit the no of clauses to 500k so we can have non-trivial ones
            no_of_clauses = random.randint(min(100000, 10 * variables), min(500000, 200 * variables))
            max_len = int(1000000 / no_of_clauses)
            return no_of_clauses, min(max_len, max(3, int(0.05 * variables)))
        elif self is ModeClauses.BALANCED:
            no_of_clauses = random.randint(variables, 3 * variables)
            max_len = int(1000000 / no_of_clauses)
            return no_of_clauses, min(max_len, variables)
        elif self is ModeClauses.FEW_AND_LONG:
            no_of_clauses = random.randint(max(1, int(0.05 * variables)), max(1, int(0.4 * variables)))
            max_len = int(1000000 / no_of_clauses)
            return no_of_clauses, min(max_len, random.randint(variables + 1, variables * 40))
        elif self is ModeClauses.MANY_AND_LONG:
            # If too many variables, re-use the balanced mode, as this one will generate a LOT of literals.
            if variables > 500:
                return ModeClauses.BALANCED.get_clause_parameters(variables)
            else:
                no_of_clauses = random.randint(10 * variables, 50 * variables)
                max_len = int(1000000 / no_of_clauses)
                return no_of_clauses, random.randint(variables + 1, min(max_len, variables * 30))
        elif self is ModeClauses.SPECIAL:
            # TODO: implement this. Basically goes into the extremes
            return ModeClauses.BALANCED.get_clause_parameters(variables)

class ModeVariables(Enum):
    """
    Describes the generating mode for number of variables of the fuzzer in ub mode.
    SMALL means 1-5 variables, MEDIUM means 6-30 variables, LARGE means 31-100 variables, XLARGE means 101-1000
    variables, XXLARGE means 1001-5000 variables, UBER means stress-testing with 20k variables.
    Clauses, if unspecified, have no redundancy and at most 'variables' literals.
    """
    SMALL = 1,
    MEDIUM = 2,
    LARGE = 3,
    XLARGE = 4,
    XXLARGE = 5
    UBER = 6

    def get_variables(self):
        if self is ModeVariables.SMALL:
            return random.randint(1, 5)
        elif self is ModeVariables.MEDIUM:
            return random.randint(6, 30)
        elif self is ModeVariables.LARGE:
            return random.randint(31, 100)
        elif self is ModeVariables.XLARGE:
            return random.randint(101, 1000)
        elif self is ModeVariables.XXLARGE:
            return random.randint(1001, 5000)
        elif self is ModeVariables.UBER:
            return 20000
