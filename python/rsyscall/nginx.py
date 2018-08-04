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

# OK so my opinion is that people should write Nginx or whatever modules on their own
# For their specific use case, if they have a complicated use case or something
# And when doing that, they can build the config on their own by hand-writing it,
# and use templating as appropriate, or whatever.
# If it's simple, then they can use something off the shelf.
# And my simple thing doesn't need to extend to their use case
# And I can just use templating.
# I don't need to support multiple vservers, or multiple locations, or anything.
# Well okay maybe I do, as just basic things.
# No, no I don't, that's overcomplicated for an example.
def _build_static_config(address: rsc.Address, data: rsc.Path) -> str:
    # ok so now we need to learn how to print inet addresses with a pretty string
    # we have to make sure to pass down the dirfd to nginx
    return config

class NginxExecutable:
    def __init__(self, executable_path: rsc.Path) -> None:
        self.executable_path = executable_path

    async def exec(stdtask: rsc.StandardTask, sockfd: rsc.FileDescriptor[rsc.SocketFile], data: rsc.Path) -> rsc.ChildTask:
        rsc.assert_same_task(stdtask.task, sockfd, data)
        address = await sockfd.getsockname()
        async with data.as_argument() as datapath:
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
            """ % in_nginx_format(address), datapath
        # we should have some kind of as_argument contextmanager
        # which does nothing on exit if exec failed?
        # also, execve should accept paths as an argument,
        # and automatically mark the dirfd inside as cloexec?
        # maybe fspathing should automatically mark a thing as cloexec....
        # oh wait but we can't do that, because marking cloexec is async
        # so yeah we need our own protocol, and that is fine
        # as_argument or something
        # and I guess it does need to be a contextmanager so we can bail out
            async with (await stdtask.mkdtemp()) as workdir:
                stdtask.execve(self.executable_path, [
                    "nginx", "-p", workdir,
                    "-c", await rsc.spit(workdir/"nginx.conf", config)],
                               
                                       nginx -p ng -c nginx.conf
                # nginx requires a directory in which to store temporary files
                # created during operation; this will be that directory.
                pass
