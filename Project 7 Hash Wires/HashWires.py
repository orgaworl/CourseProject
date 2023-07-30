import secrets
import hashlib
import random
import math


class HashChains:
    def __init__(self, int_value=None):
        self.seeds = []
        self.hash_chains = {}
        self.mdp = []
        self.commitments = []

        # set values when it's possible
        if int_value:
            self.create_hash_chains(int_value)
            self.create_mdp_list(int_value)
            self.create_commitments()

    def set_hash_chains(self, seeds=None, hash_chains=None):
        if (seeds and hash_chains) and \
                (len(seeds) == len(hash_chains)):
            self.seeds = seeds
            self.hash_chains = hash_chains
        elif seeds and not hash_chains:
            # update hashchain when seed is changed
            # mdp must be set before this is used!
            self.create_hash_chains(self.mdp[0], seeds)

    def create_hash_chains(self, int_value, seeds=None):
        if seeds:
            h, s = multi_hash_chain_generate(int_value, seeds)
        else:
            h, s = multi_hash_chain_generate(int_value)
        # set values
        self.set_hash_chains(s, h)

    def create_mdp_list(self, int_value):
        self.mdp = find_mdp_simple(int_value)

    def create_commitments(self):
        self.commitments = commitment_hash_wire_generate(self.mdp, self.hash_chains)


def seed_generate():  # 生成种子
    return secrets.token_hex()


def hash_chain_generate(len, seed=None):
    if seed is None:
        seed = seed_generate()
    commitment = seed

    hash_chain = []
    for i in range(len):
        commitment = hashlib.sha256(commitment.encode('ascii')).hexdigest()
        hash_chain.append(commitment)
    return hash_chain, seed


def find_mdp_simple(value, base=10):
    exp = base
    mdp_list = [value]
    prev = value
    while exp < value:
        if (value + 1) % exp != 0:
            temp = int(value / exp) * exp - 1
            if prev != temp:
                mdp_list.append(temp)
                prev = temp
        exp *= base
    return mdp_list


def multi_hash_chain_generate(value, seeds=None):
    num = math.ceil(math.log10(value + 1))
    if not seeds:
        seeds = [seed_generate() for i in range(num)]
    multi_hash_chain = {i: hash_chain_generate(10, seeds[i])[0] for i in range(num)}
    return multi_hash_chain, seeds


# From hash multichain create the optimized hashwire
def hash_wire_commitment_generate(mdp_list, multi_hash_chain):
    # convert mdp_value to a list of digits
    digits = [int(d) for d in str(mdp_list)]
    # one mdp value can be shorter than the other
    diff = len(multi_hash_chain) - len(digits)

    return [multi_hash_chain[i + diff][digit] for i, digit in enumerate(digits)]


# create list of hash wire for every mdp value
def commitment_hash_wire_generate(mdp_list, multi_hash_chain):
    return {value: hash_wire_commitment_generate(value, multi_hash_chain) for value in mdp_list}


# number to prove geq
# hash_zero public hash
# proof_digest_n hash used to prove it's larger than n
def hash_proof_generate(n, hash_zero, proof_digest_n):
    # sanity check
    if (len(proof_digest_n) != 64) or \
            (not isinstance(n, int)) or \
            (n < 0) or \
            (not isinstance(hash_zero, str)) or \
            (not isinstance(proof_digest_n, str)):
        return False

    # is it a start proof
    if n == 0 and proof_digest_n == hash_zero:
        return True
    else:
        # can hash zero be reproduced for a given range
        # were last value should be equal hash_zero
        proof_chain_digest = hash_chain_generate(n, proof_digest_n)[-1]
        return (proof_chain_digest == hash_zero)


chains = HashChains(17532)
print('MDP list is:',chains.mdp)
print('Seeds are:',chains.seeds)
for i in chains.commitments:
    print(i, chains.commitments[i])
