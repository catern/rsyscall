ns_child = local.clone(CLONE_FILES|CLONE_NEWNS)
server_child = ns_child.clone()
server_child.execve('/bin/foofs',
  ['foofs', "--mount-at", "/"])
fd = ns_child.open("/foo/bar", O_RDONLY)
parent_fd = local.use_fd(fd)
