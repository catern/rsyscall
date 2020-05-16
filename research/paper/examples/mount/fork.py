pid = clone(CLONE_NEWNS)
if pid == 0:
    try:
        mount("/home/foo/custom_foo.conf",
              "/etc/foo.conf", "", MS_BIND, "")
        child.execv('/bin/fooserver', ['fooserver'])
    except OSError as e:
        await ipc.send(e)
        os.exit(1)
else:
    result = await ipc.recv()
    if result.is_eof:
        print("successfully exec'd")
    elif result.is_exception:
        raise result.exception
