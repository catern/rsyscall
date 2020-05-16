init = local.clone(CLONE_NEWPID)
grandchild = init.clone()
grandchild.execv('/bin/fooserver', ['fooserver'])
