from dataclasses import dataclass
import typing as t

@dataclass(eq=False)
class File:
    pass

class DirectoryFile(File):
    pass

@dataclass
class Path:
    base: DirectoryFile
    components: t.List[bytes]

@dataclass
class Root:
    pass

@dataclass
class CWD:
    pass

@dataclass
class Path:
    # This is a near Path, I guess
    base: t.Union[Root, CWD, near.FileDescriptor]
    components: t.List[bytes]

@dataclass
class Path:
    # is this a far path?
    base_file: DirectoryFile
    base: t.Union[Root, CWD, near.FileDescriptor]
    components: t.List[bytes]

@dataclass
class FileDescriptor:
    number: int

@dataclass(eq=False)
class FDTable:
    pass

@dataclass
class FileDescriptor:
    fd_table: FDTable
    fd: FileDescriptor

@dataclass
class FileHandle:
    file: File
    fd: near.FileDescriptor
    task: Task

@dataclass
class FSInfo:
    root: DirectoryFile
    cwd: DirectoryFile

@dataclass
class RootHandle:
    file: DirectoryFile
    task: Task

@dataclass
class CWDHandle:
    file: DirectoryFile
    task: Task

@dataclass
class PathHandle:
    base: t.Union[RootHandle, CWDHandle, FileHandle]
    components: t.List[bytes]

# Then I guess I can inherit handles between tasks based on,
# whether my FSInfo currently points to the same file?
# And, I guess, whether my FDTable is the same *and* that fd number points to the same file?
# Er, no...

@dataclass(eq=False)
class FDTable:
    files: t.Dict[near.FileDescriptor, File]

@dataclass
class FileHandle:
    file: File
    fd: near.FileDescriptor
    task: Task

# okay so I guess I don't need the invalidate field
# I don't need the list of file handles
# well let's review that for certainty...
# oh I do lol
# for inheritance.
# I guess I can still replace the valid field though
# Can I?
# I guess if I remove it from the list of handles, then it won't be preserved anymore...
# yeah I guess I don't need several things there
# Urgh no that's not right I don't htink

# bah!
# let's just do it.
