# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from dataclasses import dataclass
from typing import Any, Optional, List

try:
    from LightPacket.LightBPF.Lexer import Token
except ImportError:
    from LightBPF.Lexer import Token


# ----------------------------------------------------------------------
# AST
# ----------------------------------------------------------------------
class ASTNode:
    """Base class for all AST nodes."""


@dataclass
class BinaryOpNode(ASTNode):
    left: ASTNode
    op: str
    right: ASTNode


@dataclass
class UnaryOpNode(ASTNode):
    op: str
    expr: ASTNode


@dataclass
class ProtocolNode(ASTNode):
    """Standalone protocol check: 'tcp', 'ip6', 'arp'."""
    name: str
    proto_num: Optional[int] = None


@dataclass
class KeywordFilterNode(ASTNode):
    """
    'port 80', 'src host 1.2.3.4', 'tcp dst port 443', 'net 10.0.0.0/8',
    'net 10.0.0.0 mask 255.0.0.0', 'less 100', 'broadcast', 'ip proto 6'.
    """
    keyword: Optional[str]
    value: Any = None
    direction: Optional[str] = None      # 'src' | 'dst' | 'src or dst' | 'src and dst'
    protocol: Optional[str] = None       # 'tcp', 'ip6', 'ether' ...
    value_type: Optional[str] = None     # 'ipv4','ipv6','mac','cidr4','cidr6','number','range','name'
    mask: Optional[str] = None           # for 'net X mask Y'


@dataclass
class ByteAccessNode(ASTNode):
    """tcp[13], ip[2:2], ether[0], ip6[6], tcp[tcpflags]."""
    protocol: str
    offset: ASTNode
    size: int = 1


@dataclass
class LengthNode(ASTNode):
    """'len' used as an arithmetic operand."""


@dataclass
class NumberNode(ASTNode):
    value: int


@dataclass
class LiteralNode(ASTNode):
    value: str
    kind: str = "identifier"


@dataclass
class FieldNode(ASTNode):
    """Named pseudo-field: tcpflags, icmptype ..."""
    name: str


# ----------------------------------------------------------------------
# Parser
#
# Grammar (lowest -> highest precedence):
#   or_expr   := and_expr  ( ('or'|'||')  and_expr )*
#   and_expr  := not_expr  ( ('and'|'&&') not_expr )*        (juxtaposition
#                                                            also means 'and'
#                                                            only inside quals)
#   not_expr  := ('not'|'!') not_expr | primary
#   primary   := '(' or_expr ')' | qualifier_rule | relation
#   relation  := arith ( relop arith )?
#   arith     := bit_or
#   bit_or    := bit_xor ('|' bit_xor)*
#   bit_xor   := bit_and ('^' bit_and)*
#   bit_and   := shift   ('&' shift)*
#   shift     := add     (('<<'|'>>') add)*
#   add       := mul     (('+'|'-') mul)*
#   mul       := atom    (('*'|'/'|'%') atom)*
# ----------------------------------------------------------------------
_ADDR_TYPES = {
    'IPV4': 'ipv4', 'IPV6': 'ipv6', 'MAC': 'mac',
    'IPV4_CIDR': 'cidr4', 'IPV6_CIDR': 'cidr6',
}


class BpfParser:
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0

    # ---------------- navigation ----------------
    def current(self) -> Optional[Token]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def peek(self, n: int = 1) -> Optional[Token]:
        i = self.pos + n
        return self.tokens[i] if i < len(self.tokens) else None

    def advance(self) -> Optional[Token]:
        tok = self.current()
        self.pos += 1
        return tok

    def _is(self, ttype: str, value: Optional[str] = None, tok: Optional[Token] = None) -> bool:
        tok = tok or self.current()
        return bool(tok) and tok.type == ttype and (value is None or tok.value == value)

    def match(self, ttype: str, value: Optional[str] = None) -> bool:
        if self._is(ttype, value):
            self.advance()
            return True
        return False

    def consume(self, ttype: str, value: Optional[str] = None) -> Token:
        tok = self.current()
        if not tok:
            raise SyntaxError(f"Expected {ttype} '{value or ''}', reached end of input")
        if not self._is(ttype, value):
            raise SyntaxError(f"Expected {ttype} '{value or ''}', got {tok.type} '{tok.value}'")
        return self.advance()

    # ---------------- entry ----------------
    def parse(self) -> ASTNode:
        if not self.tokens:
            raise SyntaxError("Empty filter expression")
        ast = self.expr_or()
        if self.current() is not None:
            raise SyntaxError(f"Unexpected token remaining: {self.current()}")
        return ast

    # ---------------- logical ----------------
    def expr_or(self) -> ASTNode:
        left = self.expr_and()
        while self._is('LOGICAL', 'or'):
            self.advance()
            left = BinaryOpNode(left, 'or', self.expr_and())
        return left

    def expr_and(self) -> ASTNode:
        left = self.expr_not()
        while self._is('LOGICAL', 'and'):
            self.advance()
            left = BinaryOpNode(left, 'and', self.expr_not())
        return left

    def expr_not(self) -> ASTNode:
        if self._is('LOGICAL', 'not'):
            self.advance()
            return UnaryOpNode('not', self.expr_not())
        return self.expr_primary()

    # ---------------- primary (boolean level) ----------------
    def expr_primary(self) -> ASTNode:
        tok = self.current()
        if not tok:
            raise SyntaxError("Unexpected end of expression")

        # '(' could group a boolean expr OR an arithmetic expr; try boolean
        # first, and if a relational operator follows the ')' treat it as arithmetic.
        if self._is('SYMBOL', '('):
            save = self.pos
            self.advance()
            try:
                inner = self.expr_or()
                self.consume('SYMBOL', ')')
                if not self._is('REL_OP') and not self._is('MATH_OP'):
                    return inner
            except SyntaxError:
                pass
            self.pos = save  # fall through to arithmetic relation

        # Qualifier rules (protocol / direction / keyword)
        if self._starts_qualifier_rule():
            return self._parse_qualifier_rule()

        # Otherwise: relation  (arith [relop arith])
        return self.expr_relation()

    def _starts_qualifier_rule(self) -> bool:
        tok = self.current()
        if tok.type == 'KEYWORD':
            return tok.value != 'len'          # 'len' is an arithmetic operand
        if tok.type in ('IP-PROTOCOL', 'DLT', 'ETHERTYPE'):
            # protocol followed by '[' is a byte access -> arithmetic
            return not self._is('SYMBOL', '[', self.peek())
        return False

    # ---------------- qualifier rules ----------------
    def _parse_qualifier_rule(self) -> ASTNode:
        protocol = None
        direction = None

        tok = self.current()
        if tok.type in ('IP-PROTOCOL', 'DLT', 'ETHERTYPE'):
            protocol = self.advance().value
            if not self._is_qualifier_continuation():
                return ProtocolNode(name=protocol)

        # direction
        if self._is('KEYWORD', 'src') or self._is('KEYWORD', 'dst'):
            direction = self.advance().value
            # 'src or dst' / 'src and dst'
            if self._is('LOGICAL') and self.current().value in ('or', 'and') \
                    and self.peek() and self.peek().type == 'KEYWORD' \
                    and self.peek().value in ('src', 'dst') \
                    and self.peek().value != direction \
                    and self.peek(2) and self.peek(2).type == 'KEYWORD' \
                    and self.peek(2).value not in ('src', 'dst'):
                joiner = self.advance().value
                self.advance()
                direction = f"src {joiner} dst"

        kw_tok = self.current()
        if kw_tok is None or kw_tok.type != 'KEYWORD':
            if protocol and direction is None:
                return ProtocolNode(name=protocol)
            raise SyntaxError("Expected a keyword" if kw_tok is None
                              else f"Expected a keyword, got {kw_tok.type} '{kw_tok.value}'")
        keyword = self.advance().value

        return self._parse_keyword_value(keyword, protocol, direction)

    def _is_qualifier_continuation(self) -> bool:
        tok = self.current()
        return bool(tok) and tok.type == 'KEYWORD'

    def _parse_keyword_value(self, keyword, protocol, direction) -> ASTNode:
        # No-argument keywords
        if keyword in ('broadcast', 'multicast', 'inbound', 'outbound', 'gateway') \
                and not self._value_follows():
            return KeywordFilterNode(keyword=keyword, direction=direction, protocol=protocol)

        # 'len' inside qualifier position is unusual, treat as relation
        if keyword in ('less', 'greater'):
            val = self.consume('NUMBER')
            return KeywordFilterNode(keyword, int(val.value), direction, protocol, 'number')

        if keyword == 'proto' or keyword == 'protochain':
            t = self.current()
            if t is None or t.type not in ('NUMBER', 'IP-PROTOCOL', 'ETHERTYPE', 'IDENTIFIER'):
                raise SyntaxError(f"Expected protocol after '{keyword}'")
            self.advance()
            return KeywordFilterNode(keyword, t.value, direction, protocol,
                                     'number' if t.type == 'NUMBER' else 'name')

        if keyword == 'vlan' or keyword == 'mpls':
            if self._is('NUMBER'):
                return KeywordFilterNode(keyword, int(self.advance().value), direction, protocol, 'number')
            return KeywordFilterNode(keyword, None, direction, protocol)

        if keyword == 'portrange':
            rng = self.consume('RANGE').value
            lo, hi = (int(x) for x in rng.split('-'))
            if lo > hi:
                raise SyntaxError(f"Invalid port range '{rng}'")
            return KeywordFilterNode(keyword, (lo, hi), direction, protocol, 'range')

        if keyword == 'port':
            t = self.current()
            if t and t.type == 'NUMBER':
                self.advance()
                return KeywordFilterNode(keyword, int(t.value), direction, protocol, 'number')
            if t and t.type in ('IDENTIFIER', 'IP-PROTOCOL'):   # service name e.g. 'http'
                self.advance()
                return KeywordFilterNode(keyword, t.value, direction, protocol, 'name')
            raise SyntaxError("Expected port number or service name")

        if keyword == 'mask':
            raise SyntaxError("'mask' must follow 'net <address>'")

        if keyword in ('host', 'net', 'gateway'):
            t = self.current()
            if t is None:
                raise SyntaxError(f"Expected a value after '{keyword}'")
            if t.type in _ADDR_TYPES:
                self.advance()
                node = KeywordFilterNode(keyword, t.value, direction, protocol, _ADDR_TYPES[t.type])
                if keyword == 'net' and self._is('KEYWORD', 'mask'):
                    self.advance()
                    m = self.consume('IPV4')
                    node.mask = m.value
                return node
            if t.type == 'NUMBER' and keyword == 'net':         # classful: net 10
                self.advance()
                return KeywordFilterNode(keyword, t.value, direction, protocol, 'number')
            if t.type == 'IDENTIFIER':                          # hostname
                self.advance()
                return KeywordFilterNode(keyword, t.value, direction, protocol, 'name')
            raise SyntaxError(f"Invalid value for '{keyword}': {t.type} '{t.value}'")

        raise SyntaxError(f"Unsupported keyword '{keyword}'")

    def _value_follows(self) -> bool:
        t = self.current()
        return bool(t) and t.type in (*_ADDR_TYPES.keys(), 'NUMBER', 'IDENTIFIER')

    # ---------------- relation / arithmetic ----------------
    def expr_relation(self) -> ASTNode:
        left = self.expr_bitor()
        if self._is('REL_OP'):
            op = self.advance().value
            right = self.expr_bitor()
            return BinaryOpNode(left, op, right)
        return left

    def _binary_level(self, sub, ops):
        left = sub()
        while self._is('MATH_OP') and self.current().value in ops:
            op = self.advance().value
            left = BinaryOpNode(left, op, sub())
        return left

    def expr_bitor(self):   return self._binary_level(self.expr_bitxor, ('|',))
    def expr_bitxor(self):  return self._binary_level(self.expr_bitand, ('^',))
    def expr_bitand(self):  return self._binary_level(self.expr_shift, ('&',))
    def expr_shift(self):   return self._binary_level(self.expr_additive, ('<<', '>>'))
    def expr_additive(self): return self._binary_level(self.expr_mult, ('+', '-'))
    def expr_mult(self):    return self._binary_level(self.expr_atom, ('*', '/', '%'))

    def expr_atom(self) -> ASTNode:
        tok = self.current()
        if not tok:
            raise SyntaxError("Unexpected end of expression")

        if self._is('SYMBOL', '('):
            self.advance()
            e = self.expr_bitor()
            self.consume('SYMBOL', ')')
            return e

        # unary minus
        if self._is('MATH_OP', '-'):
            self.advance()
            return BinaryOpNode(NumberNode(0), '-', self.expr_atom())

        if tok.type == 'NUMBER':
            self.advance()
            return NumberNode(int(tok.value))

        if tok.type == 'KEYWORD' and tok.value == 'len':
            self.advance()
            return LengthNode()

        if tok.type == 'FIELD':
            self.advance()
            return FieldNode(tok.value)

        if tok.type in ('IP-PROTOCOL', 'DLT', 'ETHERTYPE'):
            proto = self.advance().value
            if self._is('SYMBOL', '['):
                return self._parse_byte_access(proto)
            return ProtocolNode(name=proto)

        if tok.type in _ADDR_TYPES:
            self.advance()
            return LiteralNode(tok.value, _ADDR_TYPES[tok.type])

        if tok.type == 'IDENTIFIER':
            self.advance()
            return LiteralNode(tok.value)

        raise SyntaxError(f"Unexpected token in expression: {tok}")

    def _parse_byte_access(self, proto: str) -> ByteAccessNode:
        self.consume('SYMBOL', '[')
        offset = self.expr_bitor()
        size = 1
        if self.match('SYMBOL', ':'):
            size = int(self.consume('NUMBER').value)
            if size not in (1, 2, 4):
                raise SyntaxError(f"Byte access size must be 1, 2 or 4 (got {size})")
        self.consume('SYMBOL', ']')
        return ByteAccessNode(protocol=proto, offset=offset, size=size)


# ----------------------------------------------------------------------
def pretty_print_ast(node, indent=0):
    prefix = "  " * indent
    if isinstance(node, BinaryOpNode):
        print(f"{prefix}BinaryOp ({node.op}):")
        pretty_print_ast(node.left, indent + 1)
        pretty_print_ast(node.right, indent + 1)
    elif isinstance(node, UnaryOpNode):
        print(f"{prefix}UnaryOp ({node.op}):")
        pretty_print_ast(node.expr, indent + 1)
    elif isinstance(node, ByteAccessNode):
        print(f"{prefix}ByteAccess {node.protocol}[size={node.size}]:")
        pretty_print_ast(node.offset, indent + 1)
    else:
        print(f"{prefix}{node}")