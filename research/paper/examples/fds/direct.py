db_fd = local.open("/var/db/database.db", O_RDWR)
child = local.clone()
child_fd = child.inherit_fd(db_fd)
child_fd.fcntl(F_SETFD, 0)
child.execv("/bin/fooserver",
  ["fooserver", "--database-fd", str(int(child_fd))])
