"""A class providing introspectable access to a set of processes, useful for a basic UI

We wrap functionality and annotate it with additional information, to
provide a functional UI.

"""
# html functions
import xml.etree.ElementTree as ET
import typing as t
from bs4 import BeautifulSoup
# actual stuff
from rsyscall import (
    Int32, local_thread, ChildThread, Path, Command, AsyncChildProcess,
    FileDescriptor, Task,
    Pointer, ReadablePointer, WrittenPointer, LinearPointer,
    MemoryMapping,
    AsyncFileDescriptor,
)
# TODO should we actually import this from rsyscall instead?  ChildState is a
# subset of struct siginfo, but it doesn't exist under the name of "ChildState"
# in the manpages - it's not actually named at all.
from rsyscall.sys.wait import ChildState
from rsyscall.unistd import Pipe
from rsyscall.sys.socket import AF, SOCK, Sockbuf, SOL, SO
from rsyscall.netinet.in_ import SockaddrIn
import sys
import h11
from wsgiref.handlers import format_date_time
# introspection stuff
import inspect
import typing
import enum
import itertools
from dataclasses import dataclass
from os import fsdecode
from sortedcontainers import SortedList
import re
import logging

logger = logging.getLogger(__name__)

ElemStr = t.Union[ET.Element, str]
ListElemStr = t.List[ElemStr]

def tag(tag: str, *contents: ElemStr, **attrib) -> ET.Element:
    """creates an ET.Element, and sets its children and text node; sets
    .tail for the elements passed in.

    """
    elem = ET.Element(tag, **{key: val for key, val in attrib.items() if val is not None})
    prev_child = None
    for content in contents:
        if isinstance(content, str):
            if prev_child is not None:
                prev_child.tail = (prev_child.tail or "") + content
            else:
                elem.text = (elem.text or "") + content
        else:
            elem.append(content)
            prev_child = content
    return elem

def html(*contents: ElemStr) -> ET.Element:
    return tag('html', *contents, xmlns="http://www.w3.org/1999/xhtml")

def head(*contents: ElemStr) -> ET.Element:
    return tag('head', *contents)

def body(*contents: ElemStr) -> ET.Element:
    return tag('body', *contents)

def p(*contents: ElemStr) -> ET.Element:
    return tag('p', *contents)

def details(*contents: ElemStr, open=False, style: str=None) -> ET.Element:
    elem = tag("details", *contents, style=style)
    if open:
        # defaults to False in HTML
        elem.set('open', 'true')
    return elem

def summary(*contents: ElemStr, id: str=None) -> ET.Element:
    return tag('summary', *contents, id=id)

def button(*contents: ElemStr, name: str=None, value: str=None,
           formaction: str=None) -> ET.Element:
    elem = tag('button', *contents)
    if name is not None:
        elem.set('name', name)
    if value is not None:
        elem.set('value', value)
    if formaction is not None:
        elem.set('formaction', formaction)
    return elem

def input(*contents: ElemStr, type: str, name: str, value: str=None, required: bool=False,
          list: str=None,
          placeholder: str=None,
          autofocus: bool=False,
          checked: bool=False,
) -> ET.Element:
    elem = tag('input', *contents, type=type, name=name, value=value,
               list=list, placeholder=placeholder)
    if required:
        elem.set('required', 'required')
    if autofocus:
        elem.set('autofocus', 'autofocus')
    if checked:
        elem.set('checked', 'checked')
    return elem

def label(*contents: ElemStr) -> ET.Element:
    return tag('label', *contents)

def form(*contents: ElemStr, method: str, action: str=None) -> ET.Element:
    elem = tag('form', *contents, method=method, action=action)
    return elem

def option(*contents: ElemStr, value: str,
           disabled: bool=False, selected: bool=False) -> ET.Element:
    elem = tag('option', *contents, value=value)
    if disabled:
        elem.set('disabled', 'disabled')
    if selected:
        elem.set('selected', 'selected')
    return elem

def optgroup(*contents: ElemStr, label: str) -> ET.Element:
    return tag('optgroup', *contents, label=label)

def select(*contents: ElemStr, name: str, required: bool=False) -> ET.Element:
    elem = tag('select', *contents, name=name)
    if required:
        elem.set('required', 'required')
    return elem

def datalist(*contents: ElemStr, id: str) -> ET.Element:
    return tag('datalist', *contents, id=id)

def div(*contents: ElemStr) -> ET.Element:
    return tag('div', *contents)

def span(*contents: ElemStr, id: str=None) -> ET.Element:
    elem = tag('span', *contents, id=id)
    return elem

def ul(*contents: ElemStr) -> ET.Element:
    return tag('ul', *contents)

def ol(*contents: ElemStr, start: int=None) -> ET.Element:
    elem = tag('ol', *contents)
    if start is not None:
        elem.set('start', str(start))
    return elem

def a(*contents: ElemStr, href: str) -> ET.Element:
    return tag('a', *contents, href=href)

def li(*contents: ElemStr) -> ET.Element:
    return tag('li', *contents)

def prettify(elem: ET.Element) -> str:
    return BeautifulSoup(ET.tostring(elem), 'html.parser').prettify()

class HTTPServer:
    def __init__(self, read: t.Callable[[], t.Awaitable[bytes]],
                 write: t.Callable[[bytes], t.Awaitable[None]]) -> None:
        self.read = read
        self.write = write
        self.connection = h11.Connection(our_role=h11.SERVER)

    def get_basic_headers(self) -> t.List[t.Tuple[str, str]]:
        return [
            ("Data", format_date_time(None)),
            ("Server", "foobar"),
        ]

    async def next_event(self) -> t.Any:
        while True:
            event = self.connection.next_event()
            if event is h11.NEED_DATA:
                if self.connection.they_are_waiting_for_100_continue:
                    to_write = self.connection.send(h11.InformationalResponse(
                        status_code=100,
                        headers=self.get_basic_headers(),
                    ))
                    await self.write(to_write)
                read_bytes = await self.read()
                self.connection.receive_data(read_bytes)
                continue
            return event

    async def respond(self, data: bytes, content_type: str) -> None:
        response = h11.Response(
            status_code=200,
            headers=[
                # *self.get_basic_headers(),
                ("Content-Type", content_type),
                ("Content-Length", str(len(data))),
            ])
        to_write = self.connection.send(response)
        to_write += self.connection.send(h11.Data(data=data))
        to_write += self.connection.send(h11.EndOfMessage())
        await self.write(to_write)

def a_by_id(obj: t.Any, name: str=None) -> ET.Element:
    return a(name or str(obj), href="#" + str(id(obj)))

def span_by_id(obj: t.Any) -> ET.Element:
    return span(str(obj), id=str(id(obj)))

@dataclass
class Result:
    val: t.Any
    obj: t.Any
    method_name: str
    bound_args: inspect.BoundArguments

    def _render_val(self, val: t.Any) -> t.List[ElemStr]:
        if isinstance(val, (int, str, bytes, ChildState, type, type(None))):
            return [str(val)]
        elif isinstance(val, Exception):
            # TODO put traceback in a details element
            return ["Raised ", repr(val)]
        elif isinstance(val, tuple):
            elems: t.List[ElemStr] = ["("]
            for x in val:
                elems.extend(self._render_val(x))
                elems.append(",")
            elems[-1] = ")"
            return elems
        elif isinstance(val, Pipe):
            return [
                a_by_id(val, "Pipe"),
                "(read=", a_by_id(val.read),
                ", write=", a_by_id(val.write),
                ")",
            ]
        else:
            return [a_by_id(val)]

    def _render_call(self) -> t.List[ElemStr]:
        elems: t.List[ElemStr] = ['(']
        for arg in self.bound_args.args:
            elems.extend(self._render_val(arg))
            elems.append(",")
        for key, arg in self.bound_args.kwargs.items():
            elems.append(f'{key}=')
            elems.extend(self._render_val(arg))
            elems.append(",")
        if len(elems) > 1:
            elems.pop()
        elems.append(')')
        return elems

    def render_result(self) -> ET.Element:
        if self.val is None:
            return span(
                a_by_id(self.obj),
                '.' + self.method_name,
                *self._render_call(),
                ' ran and returned None.',
            )
        else:
            return span(
                a_by_id(self.obj),
                "." + self.method_name,
                *self._render_call(),
                ":",
                *self._render_val(self.val),
            )

def get_task(obj: t.Any) -> Task:
    if isinstance(obj, FileDescriptor):
        return obj.task
    elif isinstance(obj, ChildThread):
        return obj.task
    elif isinstance(obj, Task):
        return obj
    elif isinstance(obj, AsyncChildProcess):
        return obj.process.task # type: ignore
    else:
        raise Exception("can't get task from", obj)

def get_pointer_type(obj: Pointer) -> t.Type:
    hints = typing.get_type_hints(obj.serializer.to_bytes)
    sig = inspect.signature(obj.serializer.to_bytes)
    first_param_name = next(iter(sig.parameters.values())).name
    typ = hints[first_param_name]
    globls = obj.serializer.to_bytes.__globals__ # type: ignore
    if isinstance(typ, type):
        return typ
    else:
        return typ.__bound__._evaluate(globls, globls)

manpage_regex = re.compile(r'.*manpage: ([a-z_0-9]*)\((\d)\).*', re.DOTALL)

def get_manpage(obj: t.Callable) -> t.Optional[t.Tuple[str, int]]:
    # so that we look at inherited docstrings
    doc = inspect.getdoc(obj)
    if not doc:
        return None
    match = manpage_regex.match(doc)
    if match:
        return match.group(1), int(match.group(2))
    else:
        return None

def iterindex(iter, index: int) -> t.Any:
    for cur, val in enumerate(iter):
        if cur == index:
            return val
    else:
        raise Exception("iterator ended before index reached")

class HTMLUI:
    def __init__(self) -> None:
        self.objects: t.Dict[int, t.Any] = {}
        self.results: t.List[Result] = []
        self.commands: t.List[Command] = []
        self.threads: t.List[ChildThread] = []
        self.task_to_fds: t.Dict[Task, t.List[t.Union[FileDescriptor, Pipe]]] = {}
        self.autofocus_command_index: t.Optional[int] = None
        self.type_to_mmap_to_pointers: t.Dict[t.Type, t.Dict[MemoryMapping, SortedList]] = {bytes: {}}
        self.datalist_id: int = 1

    def is_autofocus_command_index(self, index: int) -> bool:
        if self.autofocus_command_index == index:
            self.autofocus_command_index = None
            return True
        else:
            return False

    def get_mmap_to_pointers(self, typ: t.Type) -> t.Dict[MemoryMapping, SortedList]:
        return self.type_to_mmap_to_pointers.setdefault(typ, {})

    def get_pointer_by_indices(self, typ: t.Type, mmap_index: int, ptr_index: int) -> Pointer:
        return iterindex(iter(self.get_mmap_to_pointers(typ).values()), mmap_index)[ptr_index]

    def get_pointers_by_indices(self, typ_index: int, mmap_index: int) -> SortedList:
        mmap_to_pointers = iterindex(iter(self.type_to_mmap_to_pointers.values()), typ_index)
        return iterindex(iter(mmap_to_pointers.values()), mmap_index)

    def add_pointer(self, pointer: Pointer) -> None:
        self.type_to_mmap_to_pointers.setdefault(get_pointer_type(pointer), {}
        ).setdefault(pointer.mapping,
                     SortedList(None, key=lambda ptr:
                                ptr.allocation.offset() if ptr.valid else 0)
        ).add(pointer)

    def make_selecter(
            self, name: str, options: t.List[ET.Element], required: bool,
            placeholder: str=None,
    ) -> t.List[ET.Element]:
        # don't handle non-required selects yet
        assert required == True
        return [
            label(name,
                  select(
                      option(placeholder or '', value=''),
                      *options, name=name, required=required)),
        ]

    def render_pointer_parameter(
            self, param: inspect.Parameter, ptr_typ: t.Type, orig_typ: t.Any,
    ) -> t.List[ET.Element]:
        required = param.default is inspect.Parameter.empty
        ptrs: t.List[Pointer]
        return self.make_selecter(param.name, [
            optgroup(*[
                option(str(ptr), value=f'{mmap_idx}.{ptr_idx}')
                for ptr_idx, ptr in enumerate(ptrs)
                if ptr.valid
            ], label=str(mmap)) for mmap_idx, (mmap, ptrs)
            in enumerate(self.get_mmap_to_pointers(ptr_typ).items())
            if any(ptr.valid for ptr in ptrs)
            ], required=required, placeholder=f'Pointer[{ptr_typ.__name__}]')

    def render_parameter(
            self, obj, param: inspect.Parameter, typ: t.Type,
            placeholder: str=None,
    ) -> t.List[ET.Element]:
        required = param.default is inspect.Parameter.empty
        if isinstance(typ, type):
            if issubclass(typ, enum.IntFlag):
                default = typ(0) if required else param.default
                # skip 0 element
                flags = [flag for flag in typ if flag.value != 0]
                elems = [label(typ.__name__ + '.' + flag.name,
                               input(type="checkbox", name=param.name, value=flag.name,
                                     checked=flag in default))
                         for flag in flags]
            elif issubclass(typ, enum.IntEnum):
                return [label(param.name, select(
                    *[option(
                        typ.__name__ + '.' + variant.name, value=variant.name,
                        selected=param.default == variant,
                    ) for variant in typ],
                    name=param.name,
                ))]
            elif issubclass(typ, int):
                if not required and isinstance(param.default, int):
                    # if the parameter is optional and has an integer default,
                    # fill the input with the default and make the input required.
                    value: t.Optional[str] = str(param.default)
                    required = True
                else:
                    value = None
                elems = [label(param.name, input(
                    type="number", name=param.name,
                    value=value, required=required,
                    placeholder=placeholder or str(typ.__name__)))]
            elif issubclass(typ, Command):
                elems = self.make_selecter(param.name, [
                    option(str(cmd), value=str(i))
                    for i, cmd in enumerate(self.commands)
                ], required=required, placeholder=str(typ.__name__))
            elif issubclass(typ, Pointer):
                elems = self.render_pointer_parameter(param, bytes, Pointer[bytes])
            elif not required:
                # optional parameter - just don't include it
                return []
            else:
                raise Exception("unsupported required parameter type", param, typ)
        elif isinstance(typ, typing.TypeVar):
            # handle typing annotations
            bound = typ.__bound__
            typestring = bound.__forward_arg__
            if typestring == 'BaseFileDescriptor':
                task = get_task(obj)
                options: t.List[ET.Element] = []
                for i, val in enumerate(self.task_to_fds[task]):
                    if isinstance(val, Pipe):
                        options.append(optgroup(
                            option(f'Read FD:{val.read.near.number}',
                                   value=str(i)+".read"),
                            option(f'Write FD:{val.write.near.number}',
                                   value=str(i)+".write"),
                            label="Pipe"))
                    else:
                        options.append(option(f'FD:{val.near.number}', value=str(i)))
                elems = self.make_selecter(param.name, options, required=required,
                                           placeholder='FileDescriptor')
            elif not required:
                # optional parameter - just don't include it
                return []
            else:
                raise Exception("unsupported bound", typestring)
        elif isinstance(typ, typing._GenericAlias):
            origin = typ.__origin__
            if origin is Pointer:
                arg, = typ.__args__
                elems = self.render_pointer_parameter(param, arg, typ)
            elif origin is t.Union:
                args = typ.__args__
                # assume it's for malloc
                if isinstance(args[0], typing._GenericAlias):
                    if args[0].__args__[0].__bound__.__forward_arg__ == 'FixedSerializer':
                        types = self.type_to_mmap_to_pointers
                        elems = self.make_selecter(param.name, [
                            option(str(type), value=str(i))
                            for i, type in enumerate(types)
                        ], required,
                        placeholder="Union[Type[FixedSize], Type[Serializable]]")
                    else:
                        raise Exception("unsupported union args", args)
                elif len(args) == 2 and args[1] is type(None):
                    # it's an optional
                    return self.render_parameter(obj, param, args[0],
                                                 placeholder=f'Optional[{args[0].__name__}]')
                elif not required:
                    # optional parameter - just don't include it
                    return []
                else:
                    raise Exception("unsupported args", args)
            elif not required:
                # optional parameter - just don't include it
                return []
            else:
                raise Exception("unsupported origin", origin)
        elif not required:
            # optional parameter - just don't include it
            return []
        else:
            raise Exception("unsupported required parameter type", param, typ)
        return elems

    def render_return_type(self, typ: t.Any, obj: t.Any) -> str:
        if typ is type(None):
            return "None"
        elif isinstance(typ, typing.TypeVar):
            # handle typing annotations
            bound = typ.__bound__
            if bound is None:
                assert isinstance(obj, Pointer)
                return obj.typ.__name__
            typestring = bound.__forward_arg__
            if typestring.endswith('FileDescriptor'):
                return "FileDescriptor"
            else:
                raise Exception(typestring)
        elif isinstance(typ, typing._GenericAlias):
            origin = typ.__origin__
            if origin is tuple:
                return "(" + ",".join(self.render_return_type(typ, obj)
                                      for typ in typ.__args__) + ")"
            elif origin is t.Union:
                typargs = typ.__args__
                assert isinstance(typargs[0], typing._GenericAlias)
                assert typargs[0].__origin__ == Pointer
                return "Pointer[Serializable]"
            elif issubclass(origin, Pointer):
                arg, = typ.__args__
                return f'{origin.__name__}[{self.render_return_type(arg, obj)}]'
        elif isinstance(typ, type):
            return str(typ.__name__)
        raise Exception("unhandled return type", typ)

    def render_method(self, obj: t.Any, name: str,
    ) -> ET.Element:
        if id(obj) not in self.objects:
            self.objects[id(obj)] = obj
        method = getattr(obj, name)
        sig = inspect.signature(method)
        types = typing.get_type_hints(method)
        man = get_manpage(method)
        if man:
            manname, number = man
            manpage_elems = [a(
                'man', href=f'https://man7.org/linux/man-pages/man{number}'
                f'/{manname}.{number}.html')]
        else:
            manpage_elems = []
        required: t.List[ElemStr] = []
        optional: t.List[ElemStr] = []
        for param in sig.parameters.values():
            is_required = param.default is inspect.Parameter.empty
            param_elems = self.render_parameter(obj, param, types[param.name])
            (required if is_required else optional).extend(param_elems)
        main: t.List[ElemStr] = [
            # TODO would be nice to share this hidden input between forms
            input(type="hidden", name="object", value=str(id(obj))),
            button(name, name="method", value=name),
            "-> ", self.render_return_type(types['return'], obj), ';',
            *manpage_elems,
            *required,
        ]
        if optional:
            return form(details(summary(*main), *optional),
                        action="/", method="post")
        else:
            return form(*main, action="/", method="post")

    def render_command(self, index: int, command: Command) -> ET.Element:
        action_url = f'/command/{index}'
        return span(
            form(button('Copy', formaction=action_url + "/copy"),
                 button('Delete', formaction=action_url + "/delete"),
                 method="post"),
            form(label('Executable path',
                       input(type='text', name="executable_path",
                             value=fsdecode(command.executable_path))),
                 button('Update'),
                 action=action_url, method="post"),
            ol(*[li(fsdecode(arg)) for arg in command.arguments],
               form(label('New argument',
                          input(type='text', name="new_arg",
                                placeholder="--argument",
                          autofocus=self.is_autofocus_command_index(index))),
                    button('Add'),
                    action=action_url, method="post"),
               start=0),
            ul(*[li(key, "=", fsdecode(val)) for key, val in command.env_updates.items()],
               form(label('New environment variable',
                          input(type='text', name="new_env_key", placeholder="ENV_VAR"),
                          '=',
                          input(type='text', name="new_env_val", placeholder="value")),
                    button('Add environment variable'),
                    action=action_url, method="post"))
        )

    def render_command_list(self) -> ET.Element:
        return details(summary("Commands"),
            ol(*[li(self.render_command(idx, command))
                 for idx, command in enumerate(self.commands)],
               li(form(label('Executable path for new command',
                             input(type='text', name="executable_path",
                                   placeholder='/bin/foo')),
                       label('argv[0]',
                             input(type='text', name='argv0',
                                   placeholder='foo')),
                       button('Add new command'),
                       action='/command', method="post")),
            ), open=True)

    def render_fd(self, thread_index: int, fd_index: int,
                  fd: FileDescriptor,
                  allow_clear: bool=True
    ) -> ET.Element:
        heading = span(str(fd), id=str(id(fd)))
        if fd.valid:
            return span(heading,
                        self.render_method(fd, 'close'),
                        self.render_method(fd, 'dup2'),
                        self.render_method(fd, 'read'),
                        self.render_method(fd, 'write'),
            )
        else:
            if allow_clear:
                return span(form(tag('del', heading),
                                 " closed", button('Clear'),
                                 action=f'/thread/{thread_index}/fd/{fd_index}/clear',
                                 method='post'))
            else:
                return span(tag('del', heading))


    def render_pipe(self, thread_index: int, fd_index: int,
                    pipe: Pipe) -> ET.Element:
        heading = span("Pipe",
                       id=str(id(pipe)))
        fds = [
            li(span("Read:", self.render_fd(
                thread_index, fd_index, pipe.read, allow_clear=False))),
            li(span("Write:", self.render_fd(
                thread_index, fd_index, pipe.write, allow_clear=False))),
        ]
        if pipe.read.valid or pipe.write.valid:
            return span(heading, ul(*fds))
        else:
            return span(form(tag('del', heading), " closed", ul(*fds),
                             button('Clear'),
                             action=f'/thread/{thread_index}/fd/{fd_index}/clear',
                             method='post'))

    def render_complex_fd(self, thread_index: int, fd_index: int,
                          fd: t.Union[FileDescriptor, Pipe]) -> ET.Element:
        if isinstance(fd, FileDescriptor):
            return self.render_fd(thread_index, fd_index, fd)
        elif isinstance(fd, Pipe):
            return self.render_pipe(thread_index, fd_index, fd)
        else:
            raise Exception("unknown fd type", fd)

    def render_thread(self, index: int, thread: ChildThread) -> ET.Element:
        # TODO this is an approximation...
        is_running_syscall = bool(thread.task.sysif.running_read.running)
        process_block = details(summary(span_by_id(thread.process)),
                                self.render_method(thread.process, 'wait'),
                                self.render_method(thread.process, 'kill'),
                                open=thread.released or is_running_syscall)
        if thread.process.process.death_state:
            return details(summary(tag('del', span_by_id(thread.process))),
                           str(thread.process.process.death_state),
                           form(button('Clear'),
                                action=f'/thread/{index}/clear', method='post'),
                           open=True)
        elif thread.released:
            # thread is no longer under our control, but not dead yet
            return process_block
        else:
            # thread is alive and well
            return details(
                summary(span_by_id(thread)),
                ul(li(process_block),
                   li(details(
                       summary(*(["BLOCKED in syscall: "] if is_running_syscall else []),
                               str(thread.task), id=str(id(thread.task))),
                       self.render_method(thread, 'clone'),
                       self.render_method(thread, 'exit'),
                       self.render_method(thread, 'exec'),
                       self.render_method(thread.task, 'socket'),
                       self.render_method(thread, 'malloc'),
                       self.render_method(thread.task, 'pipe'),
                       details(summary("File descriptors"), *[
                           self.render_complex_fd(index, fd_idx, fd)
                           for fd_idx, fd
                        in enumerate(self.task_to_fds.get(thread.task, []))
                       ], open=True), open=True,
                       style=('color: gray; background-color: lightgray;'
                              if is_running_syscall else None)))),
                open=True)

    def render_threads(self) -> ET.Element:
        return details(summary("Threads"), ul(
            *[li(self.render_thread(idx, thread)) for idx, thread in enumerate(self.threads)],
        ), open=True)

    def render_results(self) -> ET.Element:
        if len(self.results) == 0:
            return span()
        return details(
            summary("Results: ", self.results[-1].render_result()),
            ol(*[li(result.render_result()) for result in self.results[-2:0:-1]]),
        )

    def render_pointer(self, typ: t.Type,
                       typ_index: int, mmap_index: int, ptr_index: int,
                       ptr: Pointer,
                       mergeable: bool,
    ) -> ET.Element:
        ptr_url = f'/typ/{typ_index}/mmap/{mmap_index}/ptr/{ptr_index}'
        merge = form(button('Merge'), action=f'{ptr_url}/merge', method='post')
        maybe_ops = [
            *([merge] if mergeable else []),
            *([self.render_method(ptr, 'split')] if typ is bytes else []),
        ]
        # add optional split if bytes
        header = span(str(ptr), id=str(id(ptr)))
        if not ptr.valid:
            return p(tag('del', header),
                     form(button('Clear'), action=f'{ptr_url}/clear', method='post'),
            )
        elif isinstance(ptr, ReadablePointer):
            return p(header,
                     *maybe_ops,
                     self.render_method(ptr, 'read'),
            )
        elif isinstance(ptr, LinearPointer):
            return p(header,
                     *maybe_ops,
                     self.render_method(ptr, 'linear_read'),
            )
        elif isinstance(ptr, WrittenPointer):
            return p(header, "=",
                     str(ptr.value),
                     *maybe_ops,
                     self.render_method(ptr, 'read'),
            )
        else:
            return p(header,
                     *maybe_ops,
            )

    def render_pointers(self) -> ET.Element:
        return details(
            summary("Pointers"),
            ul(*[
                li(details(summary(f'Pointer[{typ.__name__}]'), ul(*[
                    li(details(summary(str(mmap)), ul(*[
                        li(self.render_pointer(
                            typ,
                            typ_idx, mmap_idx, ptr_idx, ptr,
                            mergeable=ptr.valid and (
                                (ptr.allocation.offset() + ptr.allocation.size()) ==
                                (next_ptr and next_ptr.valid and
                                 next_ptr.allocation.offset()))))
                        for ptr_idx, (ptr, next_ptr)
                        in enumerate(itertools.zip_longest(ptrs, ptrs[1:], fillvalue=None))
                    ]), open=True))
                    for mmap_idx, (mmap, ptrs) in enumerate(mmap_to_ptrs.items())
                ]), open=True))
                for typ_idx, (typ, mmap_to_ptrs)
                in enumerate(self.type_to_mmap_to_pointers.items())
            ]), open=True)

    def render_page(self) -> ET.Element:
        return html(
            head(tag('meta', charset='utf-8'),
                 tag('title', "My test page"),
                 tag('link', rel="icon", href="data:,"),
                 tag('style', """
:target { background-color: yellow; }
select,
select option {
  color: #000000;
}
select,
select optgroup {
  color: #000000;
}
select:invalid,
select option[value=""] {
  color: gray;
}
"""),
            ),
            body(
                self.render_results(),
                self.render_pointers(),
                self.render_command_list(),
                self.render_threads(),
            ),
        )
    def decode_parameter(self, obj, param: inspect.Parameter,
                         typ: t.Type, args: t.List[bytes]) -> t.Any:
        if isinstance(typ, type):
            if issubclass(typ, enum.IntFlag):
                ret = typ(0)
                for arg in args:
                    ret |= typ[arg.decode()]
                return ret
            elif issubclass(typ, enum.IntEnum):
                return typ[args[0].decode()]
            elif issubclass(typ, int):
                return int(args[0])
            elif issubclass(typ, Command):
                return self.commands[int(args[0])]
            elif issubclass(typ, Pointer):
                mmap_index, ptr_index = [int(x) for x in (args[0]).split(b'.')]
                return self.get_pointer_by_indices(bytes, mmap_index, ptr_index)
            else:
                raise Exception("don't know how to decode this parameter", param, typ, args)
        elif isinstance(typ, typing.TypeVar):
            # handle typing annotations
            bound = typ.__bound__
            typestring = bound.__forward_arg__
            if typestring == 'BaseFileDescriptor':
                task = get_task(obj)
                fds = self.task_to_fds[task]
                first, *rest = args[0].split(b'.')
                fd = fds[int(args[0])]
                if isinstance(fd, FileDescriptor):
                    return fd
                else:
                    # to handle pipes
                    return getattr(fd, rest[0].decode())
            else:
                raise Exception("don't know how to decode this parameter", param, typ, args)
        elif isinstance(typ, typing._GenericAlias):
            origin = typ.__origin__
            if origin is Pointer:
                arg, = typ.__args__
                mmap_index, ptr_index = [int(x) for x in (args[0]).split(b'.')]
                return self.get_pointer_by_indices(arg, mmap_index, ptr_index)
            elif origin is t.Union:
                typargs = typ.__args__
                # assume it's for malloc
                if isinstance(typargs[0], typing._GenericAlias):
                    if typargs[0].__args__[0].__bound__.__forward_arg__ == 'FixedSerializer':
                        types = self.type_to_mmap_to_pointers
                        return list(types)[int(args[0])]
                elif len(typargs) == 2 and typargs[1] is type(None):
                    # it's an optional
                    if not args[0]:
                        return None
                    return self.decode_parameter(obj, param, typargs[0], args)
                else:
                    raise Exception("unsupported union args", typ, typargs)
            else:
                raise Exception("can't handle this genericparameter", param, typ, args)
        else:
            raise Exception("paramater type isn't a type?", param, typ, args)

    def _add_thread(self, thread: ChildThread) -> None:
        self.threads.append(thread)
        self.task_to_fds[thread.task] = [thread.stdin, thread.stdout, thread.stderr]

    def handle_result(self, result: Result) -> None:
        self.results.append(result)
        if isinstance(result.val, tuple):
            values: t.Iterable[t.Any] = result.val
        else:
            values = [result.val]
        for value in values:
            if isinstance(value, ChildThread):
                self._add_thread(value)
            elif isinstance(value, FileDescriptor):
                fds = self.task_to_fds.setdefault(value.task, [])
                if value not in fds:
                    fds.append(value)
            elif isinstance(value, Pipe):
                # grab the task out of the Pipe itself
                fds = self.task_to_fds.setdefault(value.write.task, [])
                if value not in fds:
                    fds.append(value)
            elif isinstance(value, Pointer):
                self.add_pointer(value)

    async def eval(self, query: t.Dict[bytes, t.List[bytes]]) -> None:
        print("query", query)        
        obj_id = int(query.pop(b'object')[0])
        obj = self.objects[obj_id]
        method_name = query.pop(b'method')[0].decode()
        method = getattr(obj, method_name)
        print(method)
        sig = inspect.signature(method)
        types = typing.get_type_hints(method)
        # ok so I guess I iterate through the params, and decode the args for each one?
        positional: t.List[t.Any] = []
        keyword: t.Dict[str, t.Any] = {}
        for param in sig.parameters.values():
            typ = types[param.name]
            query_data = query.get(param.name.encode())
            if query_data is None:
                if isinstance(typ, type) and issubclass(typ, enum.IntFlag):
                    # if we don't get a value for a Flag, it means all
                    # the checkboxes were unchecked.
                    val = typ(0)
                elif param.default is inspect.Parameter.empty:
                    raise Exception("missing required parameter", param)
                else:
                    val = param.default
            else:
                val = self.decode_parameter(obj, param, typ, query_data)
            if param.kind in [param.POSITIONAL_ONLY, param.POSITIONAL_OR_KEYWORD]:
                positional.append(val)
            elif param.kind == param.KEYWORD_ONLY:
                keyword[param.name] = val
            else:
                raise Exception("unsupported param kind", param)
        bound_arguments = sig.bind(*positional, **keyword)
        try:
            logger.info("Calling %s %s %s", method, positional, keyword)
            result = method(*positional, **keyword)
            if inspect.isawaitable(result):
                result = await result
        except Exception as e:
            logger.exception("Got exception during call")
            result = e
        self.handle_result(Result(result, obj, method_name, bound_arguments))

    def process(self, target: t.List[bytes], query: t.Dict[bytes, t.List[bytes]]) -> None:
        if target[0] == b'command':
            if len(target) == 1:
                self.commands.append(Command(
                    Path(query[b'executable_path'][0].decode()),
                    [query[b'argv0'][0].decode()], {}))
            else: # len(target) >= 2
                command_index = int(target[1])
                command = self.commands[command_index]
                if len(target) == 2:
                    if b'executable_path' in query:
                        command.executable_path = Path(
                            query[b'executable_path'][0].decode())
                    if b'new_arg' in query:
                        command = command.args(query[b'new_arg'][0].decode())
                        self.autofocus_command_index = command_index
                    if b'new_env_key' in query:
                        command = command.env({
                            query[b'new_env_key'][0].decode():
                            query[b'new_env_val'][0].decode()})
                    self.commands[command_index] = command
                elif target[2] == b'copy':
                    self.commands.append(command)
                elif target[2] == b'delete':
                    del self.commands[command_index]
                else:
                    raise Exception('unknown command operation', target[2], target)
        elif target[0] == b'thread':
            thread_index = int(target[1])
            if target[2] == b'clear':
                del self.threads[thread_index]
            elif target[2] == b'fd':
                fd_index = int(target[3])
                assert target[4] == b'clear'
                del self.task_to_fds[self.threads[thread_index].task][fd_index]
            else:
                raise Exception('unknown thread operation', target[2], target)
        elif target[0] == b'typ':
            typ_index = int(target[1])
            assert target[2] == b'mmap'
            mmap_index = int(target[3])
            assert target[4] == b'ptr'
            ptr_index = int(target[5])
            if target[6] == b'clear':
                del self.get_pointers_by_indices(typ_index, mmap_index)[ptr_index]
            elif target[6] == b'merge':
                ptrs = self.get_pointers_by_indices(typ_index, mmap_index)
                new_ptr = ptrs[ptr_index].merge(ptrs[ptr_index+1])
                del ptrs[ptr_index]
                del ptrs[ptr_index]
                ptrs.add(new_ptr)
            else:
                raise Exception("unknown action on pointer", target[6])
        elif target[0] == b'debug':
            breakpoint()
        else:
            raise Exception('unknown url', target)

import urllib.parse

@dataclass
class Connection:
    connfd: AsyncFileDescriptor
    server: HTTPServer
    htmlui: HTMLUI

    async def run(self, *, task_status) -> None:
        started = False
        while True:
            ev = await self.server.next_event()
            if isinstance(ev, h11.Request):
                request = ev
                # start accumulating body
                request_body = b''
                while True:
                    ev = await self.server.next_event()
                    if isinstance(ev, h11.EndOfMessage):
                        break
                    assert isinstance(ev, h11.Data)
                    request_body += ev.data
                if request.method == b'POST':
                    queries = (urllib.parse.parse_qs(
                        request_body, keep_blank_values=True, strict_parsing=True)
                               if request_body else {})
                    if request.target == b'/':
                        # we only background this run loop once we actually need
                        # to do something blocking
                        if not started:
                            task_status.started()
                            started = True
                        await self.htmlui.eval(queries)
                    else:
                        # all POSTs to non-/ URLs are for various bookkeeping things
                        self.htmlui.process(request.target.split(b'/')[1:], queries)
                page = prettify(self.htmlui.render_page())
                await self.server.respond(page.encode(), 'application/xhtml+xml')
                self.server.connection.start_next_cycle()
            elif isinstance(ev, h11.ConnectionClosed):
                await self.connfd.close()
                break
        if not started:
            task_status.started()
            started = True

async def main() -> None:
    sockfd = await local_thread.make_afd(await local_thread.task.socket(AF.INET, SOCK.STREAM|SOCK.NONBLOCK), nonblock=True)
    await sockfd.handle.setsockopt(SOL.SOCKET, SO.REUSEADDR, await local_thread.ptr(Int32(1)))
    zero_addr = await local_thread.ptr(SockaddrIn(12345, '127.0.0.1'))
    await sockfd.handle.bind(zero_addr)
    await sockfd.handle.listen(10)
    addr = await (await (await sockfd.handle.getsockname(await local_thread.ptr(Sockbuf(zero_addr)))).read()).buf.read()
    main = await local_thread.clone()
    htmlui = HTMLUI()
    htmlui._add_thread(main)
    htmlui.commands.append((await main.environ.which('ls')).args('/'))
    htmlui.render_page()
    await htmlui.eval({b'object': [str(id(main)).encode()], b'method': [b'clone'], b'flags': [b'NONE', b'NONE']})
    await htmlui.eval({b'object': [str(id(main)).encode()], b'method': [b'malloc'],
                       b'cls': [str(list(htmlui.type_to_mmap_to_pointers).index(bytes)).encode()], b'size': [b'1024']})
    await htmlui.eval({b'object': [str(id(main)).encode()], b'method': [b'malloc'],
                       b'cls': [str(list(htmlui.type_to_mmap_to_pointers).index(Pipe)).encode()]})
    async with trio.open_nursery() as nursery:
        while True:
            connfd = await local_thread.make_afd(await sockfd.accept(SOCK.NONBLOCK), nonblock=True)
            server = HTTPServer(connfd.read_some_bytes, connfd.write_all_bytes)
            conn = Connection(connfd, server, htmlui)
            await nursery.start(conn.run)

# ok so now we need to provide some action for those clones
# ok soooo

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    import trio
    trio.run(main)
