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
