class RsyscallHangup(Exception):
    """The task we were sending syscalls to, has changed state in a way that prevents it from responding to future syscalls.

    This may be thrown by SyscallInterface
    """
    pass
