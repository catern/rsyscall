from rsyscall.wish import wish, Wish
import trio
import typing as t

async def main() -> None:
    try:
        raise Exception("um")
    except Exception as exn:
        games = await wish(Wish(t.List[str], "i wish you would tell me ur faverut games right now!!!"), from_exn=exn)
    for game in games:
        print(game, "is fun")
    number = await wish(Wish(int, "i wish you would tell me a number!!!"))
    flavor = await wish(Wish(str, "Sorry for being so rude, spirit. Could you tell me your favorite flavor of pie?"))
    pies = [f"A tasty {flavor} pie."]*number
    await wish(Wish(None, f"Here you go spirit! {number} delicious {flavor} pies! Return when you're done eating them!"))
    print("Bye spirit! See you later!")

if __name__ == "__main__":
    trio.run(main)
