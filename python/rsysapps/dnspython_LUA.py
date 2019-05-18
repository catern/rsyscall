import dns.rdata
import dns.tokenizer

class LUA(dns.rdata.Rdata):
    __slots__ = ['type', 'lua']

    def __init__(self, rdclass, rdtype, type: str, lua: str) -> None:
        super().__init__(rdclass, rdtype)
        self.type = type
        self.lua = lua

    def to_text(self, origin=None, relativize=True, **kw):
        return self.type + " \"" + self.lua + "\""

    @classmethod
    def from_text(cls, rdclass, rdtype, tok: dns.tokenizer.Tokenizer, origin=None, relativize=True):
        typ = tok.get_identifier()
        # now we spin in a loop, getting tokens, skipping whitespace...
        # until we get an eol?
        # oh, until we see an eol token, yes
        cur = tok.get()
        if cur.is_eol_or_eof():
            raise Exception("expecting some lua code")
        lua = cur.value
        while True:
            cur = tok.get()
            if cur.is_eol_or_eof():
                break
            lua += " " + cur.value
        return cls(rdclass, rdtype, typ, lua)
