import rsyscall.io as rsc
from rsyscall.io import wish, Wish
import socket
import trio
import typing as t
import logging

async def main() -> None:
    try:
        raise Exception("um")
    except Exception as exn:
        games = await wish(Wish(t.List[str], "tell me ur faverut games"), from_exn=exn)
    for game in games:
        print(game, "is fun")
    # number = await rsc.wish(int)
    # flavor = await rsc.wish(str, "Sorry for being so rude, spirit. Could you tell me your favorite flavor of pie?")
    # pies = [f"A tasty {flavor} pie."]*number
    # await rsc.wish(None, f"Here you go spirit! {number} delicious {flavor} pies! Return when you're done eating them! 'v'")
    # print("Bye spirit! See you later!")

trio.run(main)
