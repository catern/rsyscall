child = local.clone(CLONE_NEWNS)
child.mount("/home/foo/custom_foo.conf",
  "/etc/foo.conf", "", MS_BIND, "")
child.execv('/bin/fooserver', ['fooserver'])
