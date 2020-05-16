db_fd = local.open("/var/db/database.db", O_RDWR)
pid = os.fork()
if pid == 0:
    try:
        fcntl(db_fd, F_SETFD, 0)
        os.execv("/bin/fooserver",
                 ["fooserver", "--database-fd", str(int(db_fd))])
    except OSError as e:
        await ipc.send(e)
        os.exit(1)
else:
    result = await ipc.recv()
    if result.is_eof:
        print("successfully exec'd")
    elif result.is_exception:
        raise result.exception
