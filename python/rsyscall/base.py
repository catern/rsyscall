import supervise_api
import trio
import typing as t
import abc
import rsyscall.sys as SYS
import struct
import os

# Need CFFI for:
# rsyscall struct definitions
# SYS_[syscall] numbers
# other stuff?

class Pointer:
    """A pointer to memory in a syscall server
    """

def build_syscall(number=0, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0) -> bytes:
    return struct.pack("qQQQQQQ", number, arg1, arg2, arg3, arg4, arg5, arg6)

def syscall_response(data: bytes) -> int:
    ret, err = struct.unpack("qQ", data)
    if (ret == -1):
        raise OSError(err, os.strerror(err))
    return ret

class ServerInterface:
    @abc.abstractproperty
    def tofd(self) -> trio.socket.SocketType: ...
    @abc.abstractproperty
    def fromfd(self) -> trio.socket.SocketType: ...

    async def rsyscall(self, number=0, arg1=0, arg2=0, arg3=0, arg4=0, arg5=0, arg6=0):
        request = build_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6)
        await self.tofd().send(request)
        response = await self.fromfd().recv(4096)
        return syscall_response(response)

    async def splice(self, fd_in: int, fd_out: int, length: int,
                     off_in: Pointer=None, off_out: Pointer=None):
        return (await self.rsyscall(SYS.splice, fd_in, 0, fd_out, 0, length, 0))

async def remote_cat(server):
    while True:
        ret = await server.splice(0, 1, 4096)
        if (ret == 0):
            return
