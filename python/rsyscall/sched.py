from rsyscall._raw import lib # type: ignore
import enum

class UnshareFlag(enum.IntFlag):
    NONE = 0
    FILES = lib.CLONE_FILES
    FS = lib.CLONE_FS
    NEWCGROUP = lib.CLONE_NEWCGROUP
    NEWIPC = lib.CLONE_NEWIPC
    NEWNET = lib.CLONE_NEWNET
    NEWNS = lib.CLONE_NEWNS
    NEWPID = lib.CLONE_NEWPID
    NEWUSER = lib.CLONE_NEWUSER
    NEWUTS = lib.CLONE_NEWUTS
    SYSVSEM = lib.CLONE_SYSVSEM

class CLONE(enum.IntFlag):
    NONE = 0
    ### other flags for clone
    VFORK = lib.CLONE_VFORK
    CHILD_CLEARTID = lib.CLONE_CHILD_CLEARTID
    ### sharing-control
    PARENT = lib.CLONE_PARENT
    VM = lib.CLONE_VM
    SIGHAND = lib.CLONE_SIGHAND
    IO = lib.CLONE_IO
    SYSVSEM = lib.CLONE_SYSVSEM
    # valid for unshare
    FILES = lib.CLONE_FILES
    FS = lib.CLONE_FS
    NEWCGROUP = lib.CLONE_NEWCGROUP
    NEWIPC = lib.CLONE_NEWIPC
    NEWNET = lib.CLONE_NEWNET
    NEWNS = lib.CLONE_NEWNS
    NEWPID = lib.CLONE_NEWPID
    NEWUSER = lib.CLONE_NEWUSER
    NEWUTS = lib.CLONE_NEWUTS

