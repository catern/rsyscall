pid = os.fork()
if pid == 0:
    try:
        os.chdir("/dev")
        os.execv("/bin/cat", ["cat", "./null"])
    except OSError as e:
        ipc.send(e)
        os.exit(1)
else:
    result = ipc.recv()
    if result.is_eof:
        pass # success
    elif result.is_exception:
        raise result.exception
