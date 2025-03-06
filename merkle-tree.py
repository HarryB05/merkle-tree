import hashlib
from typing import List


class MerkleTree:
    def __init__(self, transactions: List[str]):
        self.transactions = transactions
        self.tree = self.build_merkle_tree()

    def hash(self, data: str) -> str:
        """Returns SHA-256 hash of input data."""
        return hashlib.sha256(data.encode()).hexdigest()

    def build_merkle_tree(self) -> List[List[str]]:
        """Constructs the Merkle tree and returns it as a list of levels."""
        tree = [[self.hash(tx) for tx in self.transactions]]

        while len(tree[-1]) > 1:
            current_level = tree[-1]
            next_level = []

            # Pairwise hashing
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left  # Handle odd nodes
                next_level.append(self.hash(left + right))

            tree.append(next_level)

        return tree

    def get_merkle_root(self) -> str:
        """Returns the Merkle root (top hash)."""
        return self.tree[-1][0] if self.tree else None

    def get_merkle_proof(self, tx_index: int) -> List[str]:
        """Generates a Merkle proof for a given transaction index."""
        proof = []
        index = tx_index
        for level in self.tree[:-1]:  # Exclude the root level
            if len(level) == 1:
                break  # Only the root remains

            sibling_index = index + 1 if index % 2 == 0 else index - 1
            if sibling_index < len(level):
                proof.append(level[sibling_index])

            # Move to the parent index
            index = index // 2

        return proof

    def verify_proof(self, tx: str, proof: List[str], root: str) -> bool:
        """Verifies a Merkle proof against the Merkle root."""
        current_hash = self.hash(tx)

        for sibling in proof:
            if current_hash < sibling:
                current_hash = self.hash(current_hash + sibling)
            else:
                current_hash = self.hash(sibling + current_hash)

        return current_hash == root


def example():
    transactions = ["Tx1", "Tx2", "Tx3", "Tx4"]
    merkle_tree = MerkleTree(transactions)

    root = merkle_tree.get_merkle_root()
    print("Merkle Root:", root)

    # Get a Merkle Proof for a transaction
    tx_index = 2  # Proving Tx3
    proof = merkle_tree.get_merkle_proof(tx_index)
    print("Merkle Proof for Tx3:", proof)

    # Verify the proof
    is_valid = merkle_tree.verify_proof("Tx3", proof, root)
    print("Proof Valid:", is_valid)


if __name__ == "__main__":
    example()
