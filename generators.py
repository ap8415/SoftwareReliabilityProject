import random
import string

'''
Returns the DIMACS header, or a malformed header, depending on the boolean parameter 'malformed'.
'''
def dimacs_header(variables, clauses, malformed = False):
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


def dimacs_clause(variables, total, nontrivial = True):
    available = list(range(-variables, 0)) + list(range(1, variables + 1))
    clause = ''
    for i in range(0, total):
        next = available[random.randint(0, len(available) - 1)]
        available.remove(next)
        # If we want to make sure the clause is nontrivial, we also remove the opposite expression.
        if nontrivial:
            available.remove(-next)
        clause = clause + f'{next} '
    return clause + '0'
