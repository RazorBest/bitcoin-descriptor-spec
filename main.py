from arpeggio import Optional, OneOrMore, EOF, ZeroOrMore
from arpeggio import RegExMatch as _
from arpeggio import ParserPython, PTNodeVisitor, visit_parse_tree


# -------------- START HELPER FUNCTIONS FOR THE GRAMMAR -----------------------

spec_type_tokens = ['sh', 'wsh', 'pk', 'pkh', 'wpkh', 'combo', 'multi', 'sortedmulti', 'multi_a', 'sortedmulti_a', 'tr', 'addr', 'raw', 'rawtr']

def create_func(spec_type):
    return lambda *args: (spec_type + '(', *args, ')')

"""
Creates helper functions for the spec_type_tokens. When we write the grammar,
instead of `'sh(', TOKEN, ')'`, we can write `sh(TOKEN)`.
"""
for spec_type in spec_type_tokens:
    globals()[spec_type] = create_func(spec_type)

# -------------- END HELPER FUNCTIONS FOR THE GRAMMAR -------------------------


def unsigned_integer(): return _(r'\d+')

def n_keys(): return unsigned_integer

def num(): return unsigned_integer

def hex_str(): return _(r'[0-9a-fA-F]+')

# Base58check encoded
# Address starts with 1 for mainnet, and with n/m for testnet
# All of them have 34 characters
def p2pkh_address(): return _(r'(1|n|m)[1-9A-HJ-NP-Za-km-z]{33}')

# Base58check encoded
# Address starts with 3 for mainnet, and with n/m for testnet
# Mainnet adress has 34 characters
# Testnet adress has 35 characters
def p2sh_address(): return [_(r'3[1-9A-HJ-NP-Za-km-z]{33}'), _(r'2[1-9A-HJ-NP-Za-km-z]{34}')]

# Bech32 or Bech32m encoded
# All of them have 42 characters
def p2wpkh_address(): return _(r'(bc|tb)1[01-9ac-hj-np-z]{39}')

# Bech32 or Bech32m encoded
# All of them have 62 characters
def p2wpsh_address(): return _(r'(bc|tb)1[01-9ac-hj-np-z]{59}')

# Bech32 or Bech32m encoded
# All of them have 62 characters
def p2tr_address(): return _(r'(bc|tb)1[01-9ac-hj-np-z]{59}')

def segwit_address(): return [p2wpkh_address, p2wpsh_address, p2tr_address]

def addr_spec(): return [p2pkh_address, p2sh_address, segwit_address]


# -------------------- START RULES FOR KEY ------------------------------------

def key_fingerprint(): return _(r'[0-9a-fA-F]{8}')

def key_origin(): return '[', key_fingerprint, ZeroOrMore('/', num, Optional(["'", 'h'])), ']'

# Constrained by KeyPublicHexUncompressedVisitor
def key_public_hex_uncompressed(): return ['04'], _(r'[0-9a-fA-F]{130}')

# Constrained by KeyPublicHexXOnlyVisitor
def key_public_hex_xonly(): return _(r'[0-9a-fA-F]{64}')

def key_public_hex_compressed(): return ['02', '03'], key_public_hex_xonly

def key_public_hex(): return [key_public_hex_compressed, key_public_hex_uncompressed]

# Base58
# Constrained by KeyPrivateWifVisitor
def key_private_wif(): return _(r"[1-9A-HJ-NP-Za-km-z]{51,52}")

# Base58. Total length must be 111
# Constrained by KeyStartB58Visitor
def key_start_b58(): return ['xpub', 'xpriv', 'tpub', 'tpriv'], _(r"[1-9A-HJ-NP-Za-km-z]{107}")

def key_simple_path(): return ZeroOrMore('/', num, Optional(["'", 'h']))

def key_multibranch(): return '<', num, ZeroOrMore(';', num), '>'

def key_extended_path():
    return key_simple_path, Optional(key_multibranch), key_simple_path, Optional(['/*', "/*'", '/*h'])

def key_extended(): return key_start_b58, key_extended_path

def key_no_uncompressed():
    return Optional(key_origin), [key_public_hex_compressed, key_extended, key_private_wif]

def key(): return Optional(key_origin), [key_public_hex, key_extended, key_private_wif]

# -------------------- END RULES FOR KEY --------------------------------------


# -------------------- START RULES FOR TAPROOT --------------------------------

def key_sequence_xonly():
    return [key, key_public_hex_xonly], ZeroOrMore(',', [key, key_public_hex_xonly])

def multi_key_tr():
   return [
        multi_a(n_keys, ',', key_sequence_xonly),
        sortedmulti_a(n_keys, ',', key_sequence_xonly),
    ]

def tree():
    return [[pk([key, key_public_hex_xonly]), multi_key_tr], ('{', tree, ',', tree, '}')]

def taproot_script(): return tr([key, key_public_hex_xonly], Optional(',', tree))

# -------------------- END RULES FOR TAPROOT ----------------------------------


# -------------------- START RULES FOR SCRIPT ---------------------------------

def script_key(): return [pk(key), pkh(key)]

def key_sequence(): return key, ZeroOrMore(',', key)

def multi_key():
   return [
        multi(n_keys, ',', key_sequence),
        sortedmulti(n_keys, ',', key_sequence),
    ]

def subscript(): return [script_key, multi_key]

def topscript():
    return [
        sh(subscript), sh(wsh(subscript)), sh(wpkh(key_no_uncompressed)), wsh(subscript),
        wpkh(key_no_uncompressed), combo(key), addr(addr_spec), raw(hex_str), rawtr(key),
    ]

def script(): return [topscript, subscript, taproot_script]

# -------------------- END RULES FOR SCRIPT -----------------------------------


def checksum(): return _(r'[0-9a-zA-Z]{8}')

def descriptor(): return script, Optional('#', checksum), EOF


class DescriptorVisitor(PTNodeVisitor):
    def visit_key_public_hex_uncompressed(self, node, children):
        data = bytes.fromhex(node.flat_str()).decode()

        x_bytes = data[1:33]
        y_bytes = data[33:65]

        x = int.from_bytes(x_bytes, "big")
        y = int.from_bytes(y_bytes, "big")

        decoded = f"{x},{y}"
        
        # Validate the uncompressed point
        parse_tree = curve_key_parser.parse(decoded)
        visit_parse_tree(parse_tree, CurveKeyVisitor(debug=self.debug))
        
        return x, y

    def visit_key_public_hex_xonly(self, node, children):
        data = bytes.fromhex(node.flat_str())
        x = int.from_bytes(data, "big")

        decoded = f"{x}"
        
        # Validate the compressed point
        parse_tree = curve_key_parser.parse(decoded)
        visit_parse_tree(parse_tree, CurveKeyVisitor(debug=self.debug))
        
        return x

    def visit_key_private_wif(self, node, children):
        data = b58decode_check(node.flat_str())

        # Validate the private key and return the parsed
        parse_tree = key_private_wif_parser.parse(data.hex())
        visit_parse_tree(parse_tree, KeyPrivateWifVisitor(debug=self.debug))

        return parse_tree

    def visit_key_start_b58(self, node, children):
        data = b58decode_check(node.flat_str())

        version = data[:4]
        depth = data[4:4+1]
        fingerprint = data[4+1:4+1+4]
        child_num = int.from_bytes(data[4+1+4:4+1+4+4], "big")
        chain_code = int.from_bytes(data[4+1+4+4:4+1+4+4+32], "big")
        key_data = data[4+1+4+4+32:4+1+4+4+32+33]

        key_data_tree = compressed_key_data_parser.parse(key_data.hex())
        visit_parse_tree(key_data_tree, CompressedKeyDataVisitor(debug=self.debug))

        return {
            "version": version,
            "depth": depth,
            "fingerprint": fingerprint,
            "child_num": child_num,
            "chain_code": chain_code,
            "key_data": key_data,
        }


# -------------------- START CURVE KEY PARSER ---------------------------------

# Constrained by FieldElemVisitor
def field_elem(): return _(r'\d+')

# Constrained by ECPointVisitor
def ecpoint(): return field_elem, ',', field_elem

def curve_key_point(): return [ecpoint, field_elem], EOF

curve_key_parser = ParserPython(curve_key_point)

class CurveKeyVisitor(PTNodeVisitor):
    def visit_field_elem(self, node, children):
        val = int(node.flat_str())
        if not is_field_element(val):
            raise ValueError(f"FieldElem {val} must be within the field")

        return val

    def visit_ecpoint(self, node, children):
        x, y = list(map(int, node.flat_str().split(",")))

        if not is_curve_point(x, y):
            raise ValueError(f"Point ({x}, {y}) is not on the secp256k1 curve")

        return val

# -------------------- END CURVE KEY PARSER -----------------------------------


# -------------------- START KEY PRIVATE WIF PARSER ---------------------------

def privkey_hex(): return _("[0-9a-f]{64}")

def privkey_hex_inwif(): return ['80', 'ef'], privkey_hex, Optional('01'), EOF

key_private_wif_parser = ParserPython(privkey_hex_inwif)

class KeyPrivateWifVisitor(PTNodeVisitor):
    def visit_privkey_hex(self, node, children):
        data = bytes.fromhex(node.flat_str()).decode()
        val = int.from_bytes(data, "big")

        if not is_exponent_element(val):
            raise ValueError(f"Element {val} can't be exponent of the generator of secp256k1")

        return val

# -------------------- END KEY PRIVATE WIF  PARSER ----------------------------

# -------------------- START COMPRESSED KEY DATA PARSER -----------------------

def compressed_key_data(): return [key_public_hex_compressed, ('00', privkey_hex)]

compressed_key_data_parser = ParserPython(compressed_key_data)

class CompressedKeyDataVisitor(KeyPrivateWifVisitor):
    pass

# -------------------- END COMPRESSED KEY DATA PARSER -------------------------


def main():
    data = 'sh(pkh(03f6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))'

    parser = ParserPython(descriptor, debug=True)
    parse_tree = parser.parse(data)
    visit_parse_tree(parse_tree, DescriptorVisitor(debug=True))
    print(parse_tree.tree_str())


# ------------ START UTIL ------------------

from collections import deque
from functools import reduce
from hashlib import sha256

# The order of the prime field used by secp256k1, as per https://www.secg.org/sec2-v2.pdf
FIELD_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
# The curve: E: y^2 = x^3 + ax + b
# The parameter a
CURVE_A = 0
# The parameter b
CURVE_B = 7

# The order of the generetor inside the elliptic curve group of secp256k1
GENERATOR_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def is_curve_point(x: int, y: int):
    return (y**2) % FIELD_ORDER == (x**3 + CURVE_A*x + CURVE_B) % FIELD_ORDER

def is_field_element(x: int):
    return 0 <= x < FIELD_ORDER

def is_exponent_element(x: int):
    return 0 <= x < GENERATOR_ORDER


BITCOIN_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# Reference: https://github.com/keis/base58/blob/master/base58/__init__.py

def _get_base58_decode_map(alphabet: bytes):
    return {ch: idx for idx, ch in enumerate(alphabet)}

def b58decode_int(v: bytes) -> int:
    """
    Decode a Base58 encoded string as an integer
    """
    map = _get_base58_decode_map(BITCOIN_ALPHABET)
    decimal = reduce(lambda acc, x: acc * 58 + map[x], v, 0)
    return decimal

def b58decode(v: bytes) -> bytes:
    """
    Decode a Base58 encoded string
    """
    padlen = len(v)
    v = v.lstrip(BITCOIN_ALPHABET[0:1])
    padlen -= len(v)

    acc = b58decode_int(v)

    return acc.to_bytes(padlen + (acc.bit_length() + 7) // 8, 'big')

def b58decode_check(v: str) -> bytes:
    '''Decode and verify the checksum of a Base58 encoded string'''

    result = b58decode(v.encode())
    result, check = result[:-4], result[-4:]
    digest = sha256(sha256(result).digest()).digest()

    if check != digest[:4]:
        raise ValueError("Invalid checksum")

    return result
# ------------ END UTIL ------------------

if __name__ == "__main__":
    main()


