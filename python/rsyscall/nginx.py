import os
import rsyscall.io as rsc

def in_nginx_format(address: rsc.Address) -> bytes:
    if isinstance(address, rsc.InetAddress):
        return address.addr_as_string().encode() + b":" + str(address.port).encode()
    elif isinstance(address, rsc.UnixAddress):
        if len(address.path) == 0:
            raise Exception("unnamed Unix socket addresses are not supported", address)
        elif address.path[0] == 0:
            raise Exception("abstract Unix sockets are not supported", address)
        return b"unix:" + address.path
    else:
        raise Exception("unsupported address type", address)

class NginxChildTask:
    def __init__(self, child_task: rsc.ChildTask, workdir: rsc.TemporaryDirectory) -> None:
        self.child_task = child_task
        self.workdir = workdir

    async def aclose(self) -> None:
        await self.child_task.kill()
        await self.workdir.cleanup()

    async def __aenter__(self) -> 'NginxChildTask':
        return self

    async def __aexit__(self, *args, **kwargs):
        await self.close()

class NginxExecutable:
    def __init__(self, executable_path: rsc.Path) -> None:
        self.executable_path = executable_path

    async def exec(self, rsctask: rsc.RsyscallTask, sockfd: rsc.FileDescriptor[rsc.SocketFile], data: rsc.Path) -> NginxChildTask:
        rsc.assert_same_task(rsctask.stdtask.task, sockfd, data)
        config = b"""
error_log stderr error;
daemon off;
events {}
http {
  access_log /proc/self/fd/1 combined;
  server {
    listen %s;
    location / {
      root %s;
      autoindex on;
    }
  }
}
        """ % (in_nginx_format(await sockfd.getsockname()), await data.as_argument())
        # we should have some kind of as_argument contextmanager
        # which does nothing on exit if exec failed?
        # also, execve should accept paths as an argument,
        # and automatically mark the dirfd inside as cloexec?
        # maybe fspathing should automatically mark a thing as cloexec....
        # oh wait but we can't do that, because marking cloexec is async
        # so yeah we need our own protocol, and that is fine
        # as_argument or something
        # and I guess it does need to be a contextmanager so we can bail out
        workdir = await rsctask.stdtask.mkdtemp()
        await (workdir.path/"logs").mkdir()
        # nginx requires a directory in which to store temporary files
        # created during operation; this will be that directory.
        # wait a second we nee
        print("rsctask pid", await rsctask.stdtask.task.syscall.getpid())
        child_task = await rsctask.execve(self.executable_path, [
            "nginx", "-p", workdir.path,
            "-c", await rsc.spit(workdir.path/"nginx.conf", config),
        ], envp={"NGINX":str(await sockfd.as_argument()) + ";"})
        return NginxChildTask(child_task, workdir)
