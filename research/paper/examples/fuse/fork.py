init_pid = clone(CLONE_NEWPID)
if init_pid == 0:
    try:
        grandchild_pid = clone()
        if grandchild_pid == 0:
            try:
                execve('/bin/foofs',
                       ['foofs', "--mount-at", "/"])
            except OSError as e:
                await ipc.send(e)
                os.exit(1)
        else:
            pass
    except OSError as e:
        await ipc.send(e)
        os.exit(1)
    ipc.send("success")
    fd = open("/foo/bar", O_RDONLY)
    ipc.send_fd(fd) # use a Unix socket
else:
    result = await ipc.recv()
    if result.is_eof:
        pass # failure
    elif result.is_exception:
        raise result.exception
    elif result.value == "success":
        parent_fd = ipc.recv_fd()
