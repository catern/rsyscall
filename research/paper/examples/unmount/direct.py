child = local.clone(CLONE_NEWNS)
exec_fd = child.open("/bin/foo_static", O_RDONLY)
db_fd = child.open("/var/db/database.db", O_RDWR)
child.umount("/", MNT_DETACH)
db_fd.fcntl(F_SETFD, 0)
child.fexec(exec,
  ["foo_static", "--database-fd", str(int(db_fd))])
