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
            return ''.join(random.choices(string.ascii_uppercase + string.digits, k=random.randint(0, 20)))


def generate_clause(variables, clause_length, redundant=False):
    # If not redundant, clause length must be at most
    # the number of variables for the code to work.
    if not redundant:
        assert (clause_length <= variables)
    # Limit clause length for big variable sets so that the SUT won't timeout
    if clause_length > (2000000/variables):
        clause_length = int(2000000 / variables)

    # Generate clause
    
    clause = random.sample(range(1, variables+1), clause_length)
    # Randomly flips a few variables in the clause
    # TODO: determine this coefficient by relation to no of clauses or something
    clause = [x if random.random() > 0.9 else -x for x in clause]
    return clause
