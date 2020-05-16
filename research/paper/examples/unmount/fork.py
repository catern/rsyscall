pid = os.fork()
if pid == 0:
    try:
        exec_fd = os.open("/bin/foo_static", O_RDONLY)
        db_fd = os.open("/var/db/database.db", O_RDWR)
        os.umount("/", MNT_DETACH)
        fcntl(db_fd, F_SETFD, 0)
        os.fexecve(exec_fd,
          ["foo_static", "--database-fd", str(int(db_fd))])
    except OSError as e:
        await ipc.send(e)
        os.exit(1)
else:
    result = await ipc.recv()
    if result.is_eof:
        print("successfully exec'd")
    elif result.is_exception:
        raise result.exception
