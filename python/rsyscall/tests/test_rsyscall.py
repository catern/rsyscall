import unittest
import rsyscall.base as rsyscall
import trio
from rsyscall.local import LocalServer
import os

def pipe():
    return trio.socket.socketpair()

class TestBase(unittest.TestCase):
    def test_run_stub(self):
        with LocalServer() as server:
            pass            

    def test_pipe(self):
        async def test():
            with LocalServer() as server:
                # make pipe in server
                # write to remote fd
                # read from other side of remote fd
                pass

    # So what do I need?
    # 1. make a pipe in remote process
    # 2. make a data socketpair in LocalServer
    # 3. call abstracted "write" on remote fd
    # 4. call abstracted "read" on remote fd
    def test_remote_cat(self):
        # The goal: Have this entire test take place in the syscall server.
        # Making pipes, splicing, reading, writing, the whole shebang.
        proc_infd, our_infd = os.pipe()
        # OK, I see. Splice requires one of the sides to be a pipe, because the pipe is the buffer we are manipulating.
        # So, we could do it with arbitrary fds, if we put a pipe in the middle?
        # Then we need to make a wrapped pipe call... better to just do that.
        # oh, wait! why am I dependent on trio?
        # I should do it entirely inside the server, right away.
        # that requires a data socketpair in the server,
        # and possibly also knowledge of the remote-side infd.
        # Actually, in general, maybe I should just do *everything* inside the server...
        # so okay, I need an idiom for reading from a remote fd.
        # that will be, I guess,
        # "splice to remote buffer, splice from remote buffer to our connection, read from our connection"
        our_outfd, proc_outfd = pipe()
        # Yeah, I have no need generically for the ability to pass an fd from my current process to a remote process.
        # Only from syscall server to sysacll server.
        # So I should just make a pipe and read/write from it..
        with LocalServer({0:proc_infd, 1:proc_outfd}) as server:
            os.close(proc_infd)
            proc_outfd.close()
            async def test():
                async with trio.open_nursery() as nursery:
                    nursery.start_soon(rsyscall.remote_cat, server)
                    data_in = b"hello"
                    os.write(our_infd, data_in)
                    # await our_infd.send(data_in)
                    data_out = await our_outfd.recv(4096)
                    self.assertEqual(data_in, data_out)
                    os.close(our_infd)
                    # our_infd.close()
                    our_outfd.close()
            trio.run(test)
        # proc_infd, our_tofd = os.pipe()
        # our_fromfd, proc_outfd = os.pipe()
        # with StubProcess({0: proc_infd, 1:proc_outfd}) as stub:
        #     with RemoteCat(stub) as cat:
        #         data = b"hello"
        #         os.write(our_tofd, data)
        #         received = os.read(our_fromfd, 4096)
        #         self.assertEqual(data, received)
        #         os.close(our_tofd)
        # os.close(our_fromfd)

if __name__ == '__main__':
    import unittest
    unittest.main()

