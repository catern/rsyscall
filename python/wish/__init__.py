"""A typed API for generically prompting the user for a typed value, typically by dropping to a REPL

The metaphor we use is "wishing" for a value of some type, and then getting back a value
of that type. We use the wish function and the Wish class to do this. We follow many
patterns of exception handling, so `wish` can be thought of as a version of `raise` which
returns a value, and `Wish` can be thought of as an Exception object; indeed, it inherits
from Exception. Like `raise` and exception handlers, `wish` will always invoke the closest
bound wish handler.

The `wish` API is sufficiently general to cover a variety of different uses. Most
basically, it can be used to drop to a REPL at any time so that the user may interact with
the program. Since `wish` is async, this can be used even in running applications without
disturbing the rest of the application, unlike alternatives like `breakpoint`.

Another application is repairing broken systems. We can model "repair" of a broken system
as wishing for a fixed version of a broken value, which will be interactively corrected by
the user. If we make such a wish, we might want the code calling wish to perform
additional automated checks on the returned value, and wish again if the checks fail.

Yet another application is simple prompting of the user for values we cannot produce
programmatically, or prompting for the user to take actions we cannot perform
programmatically. We might prompt the user for some difficult-to-encode information about
the state of the world. Or we might prompt the user to perform some action manually that
is difficult for us to do automatically. Because `wish` invokes a wish handler, we can
automate these actions after the fact, and modify our automation to our needs, without
changing the module that calls `wish`.

To wish for a value, we create a value of class Wish, which should contain the type object
that we're wishing for, and pass it to the wish function. wish will capture a traceback of
our stack, attach it to the Wish, present that Wish to the user, and return the value
returned by the user.

When we wish for a value, we invoke the closest bound WishGranter; that handles prompting
the user and providing some UI for the user to produce the value. The WishGranter may
choose to typecheck the value returned by the user to ensure that it matches the value
requested in the Wish.  If the WishGranter provides a REPL, it may want to extract local
variables from the traceback captured by wish, and present them to the user. If no
WishGranter is bound, we simply raise the Wish as an exception.

This library does not provide any WishGranters; there are several in the rsyscall.wish module.
That module provides only console REPL WishGranters, but the API is entirely extensible,
so other ways to present a REPL, or even entirely different UIs, are possible.
For example, a REPL might be presented with a web UI; perhaps even a Jupyter notebook.

A WishGranter might also be entirely or partially automatic; it could respond to different
types of Wishes automatically, based on the type wished for, the subclass of Wish used,
the message, or other attributes, and propagate other wishes up to the WishGranter bound
above it.

"""
from __future__ import annotations
from contextvars import ContextVar
import abc
import inspect
import sys
import traceback
import types
import typing as t

__all__ = [
    'Wish',
    'WishGranter',
    'wish',
    'my_wish_granter',
]

# TODO should we inherit from BaseException or Exception?
T = t.TypeVar('T')
class Wish(BaseException, t.Generic[T]):
    """A request for a value of type `return_type`

    We inherit from BaseException. When wish is called on this value, it will fill in the
    exception fields on this value, in the same way that raise would fill in the exception
    fields of any exception.

    A user can further inherit from this class to add more information to the Wish, in the
    same way one would inherit from Exception to create a more specific Exception.

    """
    return_type: t.Type[T]

    def __init__(self, return_type: t.Type[T], *args) -> None:
        self.return_type = return_type
        super().__init__(*args)

my_wish_granter: ContextVar[WishGranter] = ContextVar('my_wish_granter')
"""The WishGranter currently active for our scope.

To use a new WishGranter in some scope, set my_wish_granter to a new value, then reset it
back to the old value once you leave that scope.  A contextmanager would likely be helpful
for this.

"""

class WishGranter:
    """An object capable of responding to a wish.

    A WishGranter is not active until it is bound. When wish is called, the closest bound
    WishGranter is used to satisfy the wish. The WishGranter may itself choose to call
    wish and propagate the wish up the stack. For example, a partially automated
    WishGranter might be able to handle only certain classes of Wish, and fall back to
    wishing again when it sees other classes.

    WishGranters are bound to my_wish_granter to become active. This merely means they
    will be used by `wish`; no actual change occurs to the WishGranter object.

    Since my_wish_granter is a ContextVar, it's useful to make an analogy to exception
    handlers, because the resolution process for ContextVars, and therefore WishGranters,
    works the same way.

    """
    @abc.abstractmethod
    async def wish(self, wish: Wish[T]) -> T:
        "Satisfy this wish, returning a value of the type requested by the wish"
        pass

def _frames_to_traceback(frames: t.List[types.FrameType]) -> t.Optional[types.TracebackType]:
    "Translate a list of frames (which can be obtained from the inspect module) to a traceback"
    tb = None
    for frame in frames:
        tb = types.TracebackType(tb, frame, frame.f_lasti, frame.f_lineno)
    return tb

# TODO should switch bool to typing_extensions.Literal[False]
async def wish(wish: Wish[T], *, from_exn: t.Union[BaseException, None, bool]=False) -> T:
    """Wish for some value, as specified by the passed Wish, and get that value

    Pass `from_exn=exn` to explicitly set the cause/context for the Wish to the exception
    `exn`; this is identical in behavior to doing `raise wish from exn` with exceptions.
    Likewise, you can pass `from_exn=None` to suppress the exception cause/context.

    We use the WishGranter currently bound to my_wish_granter in our ContextVar context to
    perform the wish. This is directly analogous to using the closest bound exception
    handler to handle an exception, and works the same way.

    """
    if not isinstance(wish, Wish):
        raise Exception("wishes should be of type Wish, not", wish)
    raising_exception = sys.exc_info()[1]
    if not isinstance(from_exn, bool):
        wish.__cause__ = from_exn
    elif raising_exception:
        wish.__context__ = raising_exception

    wish.__traceback__ = _frames_to_traceback([record.frame for record in inspect.stack()[1:]])

    wish_granter = my_wish_granter.get()
    ret = await wish_granter.wish(wish)
    return ret
