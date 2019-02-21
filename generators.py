import random
import string


def dimacs_header(variables, clauses, malformed = False):
    '''
    Returns the DIMACS header, or a malformed header, depending on the boolean parameter 'malformed'.
    '''
    if not malformed:
        return f'p cnf {variables} {clauses}'
    else:
        # Try random malformations, or just random string
        if random.random() > 0.2:
            return f'q cnf {variables} {clauses}'
        elif random.random() > 0.3:
            return f'p dnf {variables} {clauses}'
        elif random.random() > 0.2:
            return f'{variables} {clauses} p cnf'
        elif random.random() > 0.2:
            return f'p p cnf {variables} {clauses}'
        else:
            return ''.join(random.choices(string.ascii_uppercase + string.digits, k=random.randint(0, 200)))


def generate_clause(variables, clause_length, redundant=False):
    clause = []
    if not redundant:
        # If not redundant, clause length must be at most the number of variables so we don't have repetition.
        assert (clause_length <= variables)
        clause = random.sample(range(1, variables + 1), clause_length)
        # Randomly flips a few variables in the clause
        clause = [x if random.random() > 0.9 else -x for x in clause]
        return clause
    else:
        # Randomly flips a few variables. Note that we do want to keep the clause non-trivial at this point.
        available_variables = [x if random.random() > 0.9 else -x for x in range(1, variables + 1)]
        while clause_length > 0:
            clause = clause + random.sample(available_variables, min(variables, clause_length))
            clause_length -= variables
        return clause
