from rsyscall._raw import ffi, lib # type: ignore
from rsyscall.io import gather_local_bootstrap, wrap_stdin_out_err
from rsyscall.io import Epoller, AsyncFileDescriptor, Path
from rsyscall.epoll import EpollEvent, EpollEventMask
import rsyscall.nginx as ng
import socket
import struct
import time
import unittest
import trio
import trio.hazmat
import rsyscall.io
import os
import logging
import signal

logging.basicConfig(level=logging.DEBUG)

class TestNginx(unittest.TestCase):
    def setUp(self):
        self.bootstrap = gather_local_bootstrap()

    def test_nginx(self) -> None:
        async def test() -> None:
            async with (await rsyscall.io.StandardTask.make_from_bootstrap(self.bootstrap)) as root_stdtask:
                rsyscall_task, _ = await root_stdtask.spawn([])
                async with rsyscall_task as stdtask:
                    # so we need to be able to cope with resources being consumed out from under us.
                    # that is pretty weird, a nice linear type system would not have such runtime behavior
                    # how would we treat this in a linear type system?
                    # well, we'd have some objects (the task)
                    # which contains resources
                    # and to close the task/exec the task, I guess we'd need to have all the resources inside the task,
                    # so that they can be properly consumed.
                    # hmm, maybe we shouldn't even have the contextmanager at all?
                    # hmm, we're creating the reosurce then passing it in to the exec,
                    # which in the normal case, consumes it.
                    # so maybe in the abnormal case, it still has a responsibility to consume it?
                    # or is it indeed in a half-finished state at that point?
                    # we need to kill the whole task to clean up all the resources inside it?
                    # also! how the heck do we clean up this temp directory!
                    # I suppose we need to create it from the root stdtask rather than from one that will be consumed.
                    # actually, maybe we shouldn't even use the contextmanager on the rsyscall_task??
                    # all tricky.
                    async with (await stdtask.mkdtemp()) as path:
                        async with (await stdtask.task.socket_unix(socket.SOCK_STREAM)) as sockfd:
                            addr = (path/"sock").unix_address(stdtask.task)
                            await sockfd.bind(addr)
                            await sockfd.listen(10)
                            executable = ng.NginxExecutable(Path.from_bytes(
                                stdtask.task, b"/home/sbaugh/.nix-profile/bin/nginx"))
                            nginx_child_task = await executable.exec(rsyscall_task, sockfd, path)
                            await trio.sleep(10)
        trio.run(test)
