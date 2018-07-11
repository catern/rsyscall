import unittest
import supervise_api
import os

class StubProcess:
    def __init__(self, extra_fds={}):
        infd, self.tofd = os.pipe()
        self.fromfd, outfd = os.pipe()
        self.process = supervise_api.Process(
            ['./rsyscall_server', str(infd), str(outfd)],
            fds={infd:infd, outfd:outfd, **extra_fds})
        os.close(infd)
        os.close(outfd)
        for val in extra_fds.values():
            os.close(val)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
        ret = self.process.wait()
        ret.check()
        self.process.close()

    def close(self):
        os.close(self.tofd)
        os.close(self.fromfd)

class RemoteCat:
    def __init__(self, stub):
        self.process = supervise_api.Process(
            ['./remote_cat', str(stub.tofd), str(stub.fromfd)],
            fds={
                stub.tofd:stub.tofd, stub.fromfd:stub.fromfd,
            })

    def __enter__(self):
        return self

    def __exit__(self, *args):
        ret = self.process.wait()
        ret.check()
        self.process.close()


def remote_cat(stub: StubProcess, infd, outfd) -> supervise_api.Process:
    proc = supervise_api.Process(['./remote_cat'], fds={0:infd, 1:outfd})
    os.close(infd)
    os.close(outfd)

class TestRsyscall(unittest.TestCase):
    def test_run_stub(self):
        with StubProcess() as stub:
            pass            

    def test_remote_cat(self):
        proc_infd, our_tofd = os.pipe()
        our_fromfd, proc_outfd = os.pipe()
        with StubProcess({0: proc_infd, 1:proc_outfd}) as stub:
            with RemoteCat(stub) as cat:
                data = b"hello"
                os.write(our_tofd, data)
                received = os.read(our_fromfd, 4096)
                self.assertEqual(data, received)
                os.close(our_tofd)
        os.close(our_fromfd)

if __name__ == '__main__':
    import unittest
    unittest.main()

