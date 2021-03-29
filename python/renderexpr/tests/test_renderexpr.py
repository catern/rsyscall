import unittest
import renderexpr.renderexpr as rxp
from pathlib import Path
import trio

def make_location() -> Path:
    return Path("tmp")

async def bar(val):
    e = E(val)
    f = F(e, val)
    return f

async def foo(nursery, otherpath: Path):
    location = make_location()
    a = A(location/"a")
    b = B(nursery)
    c = C(a, b, otherpath/"b", await bar(b))
    d = D(c, a, b, a)

class TestRenderexpr(unittest.TestCase):
    def test(self) -> None:
        mygraph = rxp.Graph.make()
        sfoo = mygraph.symbolize(foo, {
            'make_location': make_location,
            'bar': mygraph.symbolize(bar, {}),
        })
        trio.run(sfoo, "nursery", Path("other"))
        print(mygraph.dot)
        mygraph.dot.render('out.dot', format='png')
