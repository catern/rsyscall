init_pid = clone(CLONE_NEWPID)
if init_pid == 0:
    try:
        grandchild_pid = clone()
        if grandchild_pid == 0:
            try:
                os.execv('/bin/fooserver', ['fooserver'])
            except OSError as e:
                await ipc.send(e)
                os.exit(1)
        else:
            pass
    except OSError as e:
        await ipc.send(e)
        os.exit(1)
else:
    result = await ipc.recv()
    if result.is_eof:
        pass # failure
    elif result.is_exception:
        raise result.exception
    elif result.value == "success":
        pass # success
