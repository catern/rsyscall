from rsyscall.tasks.local import thread as local_thread

async def main():
    true = await local_thread.environ.which("true")
    sleep_inf = (await local_thread.environ.which("sleep")).args("inf")
    for i in range(100):
        print("doing true", i)
        procs = [await (await local_thread.clone()).exec(sleep_inf) for _ in range(500)]
        await local_thread.run(true)
        for proc in procs:
            await proc.kill()
            await proc.wait()
        print("done true")

if __name__ == "__main__":
    import trio
    trio.run(main)
