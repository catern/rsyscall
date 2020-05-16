child = local.clone()
child.chdir("/dev")
child.execv("/bin/cat", ["cat", "./null"])
