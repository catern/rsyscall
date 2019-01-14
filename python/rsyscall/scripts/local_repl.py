import rsyscall.io as rsc
import socket
import trio
import typing as t

async def main() -> None:
    async with trio.open_nursery() as nursery:
        stdtask = await rsc.build_local_stdtask(nursery)
        async with (await stdtask.mkdtemp()) as path:
            sockfd = await stdtask.task.socket_unix(socket.SOCK_STREAM)
            sock_path = path/"sock"
            addr = sock_path.unix_address()
            await sockfd.bind(addr)
            await sockfd.listen(10)
            async_sockfd = await rsc.AsyncFileDescriptor.make(stdtask.epoller, sockfd)
            print(f"socat - UNIX-CONNECT:{str(sock_path.pure)}")
            await rsc.serve_repls(async_sockfd, {'parent_locals': locals()}, None)

trio.run(main)
