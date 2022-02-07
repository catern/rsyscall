from rsyscall.tasks.local import local_process

async def main():
    true = await local_process.environ.which("true")
    sleep_inf = (await local_process.environ.which("sleep")).args("inf")
    for i in range(100):
        print("doing true", i)
        procs = [await (await local_process.fork()).exec(sleep_inf) for _ in range(500)]
        await local_process.run(true)
        for proc in procs:
            await proc.kill()
            await proc.wait()
        print("done true")

if __name__ == "__main__":
    import trio
    trio.run(main)
