# Ehud Wasserman, 315005090, Yuval Tal, 311127120

from hashlib import sha256

from cryptography import exceptions
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from base64 import b64encode, b64decode


def gen_RSA_keys():
    """
    Generate and return 2 str which reprs secret key and suitable public key
    """

    # generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # convert to str
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    # convert suitable public key to str
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem.decode(), public_pem.decode()


def my_hash(s):
    """
    Get str and return str sha256 as hex digits, as str
    """
    return sha256(s.encode()).hexdigest()


def hashed_factory(s=None):
    """
    return lambda which get Node and return fixed string s
    or if s=None return lambda which calculated due its left + right childs
    """
    if s:
        return lambda param: my_hash(s)
    return lambda node: my_hash(node.left.hashed(node.left) + node.right.hashed(node.right))


class MerkleNode:
    """
    Node in Merkel tree
    """

    def __init__(self, hashed, left=None, right=None):
        """
        Create instance of node with lambda hashed which returns str, and childs
        left should be None iff right == None, meaning, no child, but a leaf
        """
        self.hashed = hashed
        self.right = right
        self.left = left
        # save how many leaves are in the bottom of this sub-tree
        if left:
            self.leaves = left.leaves + right.leaves
        else:
            # sub-tree of 1 leaf has itself as leaf
            self.leaves = 1

    def is_full(self):
        """
        Return whether this subtree is full = power of 2
        which means has exactly 1 time the digit "1" in the number of leaves
        """
        return bin(self.leaves).count("1") == 1

    def insert(self, leaf):
        """
        Insert new leaf to this sub-tree.
        Changes the subtree, as well as self instance.
        The return value is the new root of the sub-tree after the insertion
        """

        # if full set this node as left child of new-root
        if self.is_full():
            new_root = MerkleNode(hashed_factory(), self, leaf)
            return new_root
        # else insert it to the right sub-tree
        self.right = self.right.insert(leaf)
        self.leaves += 1
        return self

    def proof_with_root(self, x):
        """
        Get proof of inclusion to leaf idx x
        """
        return self.hashed(self) + self.__proof(x + 1)

    def __proof(self, x):
        """
        Get proof of inclusion to leaf num x [start with 1]
        for inner use only. user should use proof_with_root()
        """

        # leaf not need to proof itself
        if not self.left:
            return ""
        # check if height is more than 1, meaning left sub-tree has at least 2 leaves,
        # choose which sub-tree to go (left sub-tree or right sub-tree)
        if self.left.leaves > 1:
            if x <= self.left.leaves:
                return self.left.__proof(x) + " 1" + self.right.hashed(self.right)
            else:
                return self.right.__proof(x - self.left.leaves) + " 0" + self.left.hashed(self.left)
        # height is 1, therefore self.rigth != None,
        # x can be 1 (left child) or 2 (right child)
        if x == 1:
            return " 1" + self.right.hashed(self.right)
        else:
            return " 0" + self.left.hashed(self.left)

    @staticmethod
    def check_proof(leaf, proof_str):
        """
        Static function to check if leaf is correct according to proof_str of inclusion
        """

        # proof_str has root and then steps from down to up until the root
        hashed_root = proof_str.split(" ")[0]
        rest = proof_str.split(" ")[1:]
        for node in rest:
            if not node:
                continue
            # should the proof[node] be concatenated from left?
            left = node[0] == "0"
            node = node[1:]
            node = node + leaf if left else leaf + node
            leaf = my_hash(node)
        return leaf == hashed_root

    def sign_on_root(root_to_sign, private_key: str) -> str:
        """
        Sign on the hash of this node, using private_key
        """

        # load private key object from str
        private_key = load_pem_private_key(private_key.encode(), None, default_backend())
        # get msg (hash) to sign on it
        message = root_to_sign.hashed(root_to_sign).encode()
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # return signature as 64 base in str
        return b64encode(signature).decode()


def get(multiline):
    """
    Read line from user and return the choice (part until first space) and the text for the choice (str,str),
    if choice is in multiline: read lines until empty line
    """
    firstLine = input().replace("\r\n", "\n").replace("\r", "\n")
    choice = firstLine.split(" ")[0]
    firstLine = firstLine[len(choice + " "):]
    if choice not in multiline:
        return choice, firstLine
    curr = input().replace("\r\n", "\n").replace("\r", "\n")
    while curr:
        firstLine += "\n" + curr
        curr = input().replace("\r\n", "\n").replace("\r", "\n")
    return choice, firstLine


def sign_verification(public_key: str, signature: str, message: str) -> bool:
    """
    Return if signature is valid signature of public_key of message.
    """

    # load from str to public key object
    public_key = load_pem_public_key(public_key.encode(), default_backend())
    try:
        public_key.verify(
            b64decode(signature.encode()),
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # if we here the verify succeded
        return True
    except exceptions.InvalidSignature:
        # if we here the signature of the message using secret key which suitable to the public key, isn't correct
        return False


class SparseNode:
    """
    Node in Sparse Merkel tree, where default leaves values are "0", and is full tree
    Each node contains theoretically 2 childs always.
    In reality contains both None(meaning this is deafult node) or both not None
    """

    __default = ["0"]

    @staticmethod
    def as_binary_str(digest, min_len=256):
        """
        Get hex number (as str) and return its representation as binary in str with padding to (at least) min_len digits
        """
        bin_digest = bin(int(digest, base=16))[2:]
        paddled_digest = (min_len - len(bin_digest)) * "0" + bin_digest
        return paddled_digest

    @classmethod
    def get_default(cls, height):
        """
        Get hashes from "0" to hash in of node in height until in default tree,
        if not set yet, set it in SparseNode.__default
        """

        # don't calc if already exists
        size = len(cls.__default)
        if size > height:
            return cls.__default[height]
        # else start from the end of the current SparseNode.__default and keep going
        for i in range(size - 1, height):
            cls.__default.append(my_hash(cls.__default[-1] * 2))
        return cls.__default[height]

    def __init__(self, height):
        """
        Create new default node in the given height
        """

        self.height = height
        self.right = None
        self.left = None
        if height == 0:
            self.val = "0"

    def __insert(self, digest):
        """
        Set leaf to "1" according to digest which is path through the tree.
        ("1100...0" 256 chars, meanings from root(self) go to child right right left left ... left)
        for inner use only. user should use insert_aux()
        """

        for direction in digest:
            # if this node used to be "default", set its childs as default and continue recursively
            if not self.right:
                self.left = SparseNode(self.height - 1)
                self.right = SparseNode(self.height - 1)
            self = self.left if direction == "0" else self.right
        self.val = "1"

    def insert_aux(self, digest):
        """
        Set leaf to "1" according to digest which is path through the tree. digest is hex number in str.
        """
        digest = SparseNode.as_binary_str(digest, self.height)
        if len(digest) > self.height:
            raise Exception
        self.__insert(digest)

    def get_hashed_data(self):
        """
        Get str of the hashed data from leaves untill this node
        """

        # if it leaf
        if self.height == 0:
            return self.val
        # if it default sub tree
        if not self.left:
            return SparseNode.get_default(self.height)
        # else calc the hash
        left = self.left.get_hashed_data()
        right = self.right.get_hashed_data()
        return my_hash(left + right)
        # Note: above ^^^
        # still can be deep recursion
        # however, writing as iterative much harder to understand

    def proof_aux(self, digest):
        """
        Proof of inclusion, root and then the rest of nodes
        """
        digest = SparseNode.as_binary_str(digest, self.height)
        if len(digest) > self.height:
            raise Exception
        return self.get_hashed_data() + " " + self.__proof(digest)

    def __proof(self, digest):
        """
        Returns proof of inclusion of digest(bin num as str)
        for inner use only. user should use proof_aux()
        """
        proofs = []
        # from this root until brother leaf(if not "0")
        for direction in digest:
            # if its default node
            # [self doesn't get till leaves, only self.left\self.rigth below]
            if not self.left:
                proofs.append(self.get_hashed_data())
                break
            # select next node
            next_node = self.left if direction == "0" else self.right
            brother = self.left if direction != "0" else self.right
            # save proof from the brother
            h = brother.get_hashed_data()
            proofs.append(h)
            self = next_node
        # return reversed proofs
        return " ".join(proofs[::-1])

    @staticmethod
    def check_sparse_proof(digest, leaf, proof_str, tree_height=256):
        """
        Check proof of inclusion.
        """

        paddled_digest = SparseNode.as_binary_str(digest, tree_height)[::-1]
        if len(paddled_digest) > tree_height:
            raise Exception
        hashed_root = proof_str.split(" ")[0]
        rest = proof_str.split(" ")[1:]

        curr = None

        if leaf == "0":
            # might be part of default sub-tree
            height_default_start = tree_height + 1 - len(rest)
            # check correct value, if we didn't accept 256 proofs
            if height_default_start > 0 and rest[0] != SparseNode.get_default(height_default_start):
                return False
            curr = rest[0]
            rest = rest[1:]
        else:
            curr = "1"  # == leaf
            # make sure we won't ommit brother with 'default' value
            # if rest[0] != "1" and rest[0] != "0":
            #     rest.insert(0, "0")

        # from beginning point try to get until the root
        for i in range(len(rest)):
            left = paddled_digest[i] == "0"
            concat = rest[i] + curr if not left else curr + rest[i]
            curr = my_hash(concat)
        # check it same as the root
        return curr == hashed_root


def main():
    """
    Run in infinity loop to handle option of the exercise.
    """

    sparse = SparseNode(256)
    root = None
    while True:
        try:
            choice, text = get(["6", "7"])  # assuming inputs 6/7 are multilines
            # switch-case of user choice
            if choice == "1":
                if not root:
                    root = MerkleNode(hashed_factory(text))
                else:
                    root = root.insert(MerkleNode(hashed_factory(text)))
            if choice == "2":
                print(root.hashed(root))
            if choice == "3":
                print(root.proof_with_root(int(text)))
            if choice == "4":
                leaf = text.split(" ")[0]
                hashed_leaf = my_hash(leaf)
                proof = text[len(leaf + " "):]
                print(MerkleNode.check_proof(hashed_leaf, proof))
            if choice == "5":
                sk, pk = gen_RSA_keys()
                print(sk + "\n" + pk)
            if choice == "6":
                print(root.sign_on_root(text))
            if choice == "7":
                pk = text
                signature = input().replace("\r\n", "\n").replace("\r", "\n")
                message = signature.split(" ")[1]
                signature = signature.split(" ")[0]
                print(sign_verification(pk, signature, message))
            if choice == "8":
                sparse.insert_aux(text)
            if choice == "9":
                print(sparse.get_hashed_data())
            if choice == "10":
                print(sparse.proof_aux(text))
            if choice == "11":
                digest = text.split(" ")[0]
                rest = text[len(digest + " "):]
                leaf = rest.split(" ")[0]
                proof_str = rest[len(leaf + " "):]
                print(SparseNode.check_sparse_proof(digest, leaf, proof_str))
            # invalid user-choice
            if int(choice) > 11 or int(choice) < 1:
                print()
        except KeyboardInterrupt:
            break
        except EOFError:
            break
        except:
            print()


main()
