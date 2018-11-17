from rsyscall.io import local_stdtask

class TestIO(unittest.TestCase):
    def test_pipe(self):
        async def test() -> None:
            child_thread = await local_stdtask.fork()
            command = SSHCommand()
            child_task = await command.exec(child_thread)
        trio.run(test)


