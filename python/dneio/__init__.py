"""Concurrency based on `shift`/`reset` and object-oriented effect handlers

We implement a portable `shift`/`reset`[0] for async Python, which works when running
under any supported async runner. We also build several concurrent communication
mechanisms with `shift`/`reset`.

Delimited continuations, such as `shift`/`reset`, can be used to transform a
callback-based concurrency system into a more ergonomic direct-style system.[1]
For example, we can go from:

```
def cb(data):
  if data:
    more_work(data)
file.read_cb(cb)
```

to:

```
data = await shift(file.read_cb)
if data:
  more_work(data)
```

We can then construct an ergonomic direct-style concurrency system by layering
delimited continuations on top of a traditional callback-based concurrency
system. This has a number of advantages.

Instead of a coroutine performing a blocking operation by yielding up to a
global event loop, a coroutine performs a blocking operation by calling `shift`
with any object that accepts a callback.  Context switching between running
coroutines happens automatically, in a distributed fashion, as objects receive
events and call callbacks.  Instead of relying implicitly on a global event loop
and global scheduler, a coroutine explicitly selects what object is responsible
for scheduling it, simply by making a call into that object.  That object may
perform its duties by calling into other objects or by performing blocking
system calls itself, and ultimately resumes the coroutine with the result by
calling the callback.

With callback-based concurrency, an object can guarantee that when callbacks are
registered in a certain order, the underlying operations are performed in that
order; and that when events happen in some order, the registered callbacks are
called in that same order.  This preserves information about event ordering and
allows for much simpler bookkeeping of state.  This guarantee is preserved when
using `shift`/`reset`.

For example, suppose some underlying bit of state is either "True" or "False",
and we read that state on each related operation, and maintain a Python boolean
which is supposed to match the underlying state. If callbacks are called in
order, we know that the underlying state is always equal to the state at the
time of the last callback, so we can just set the tracking bool to the bit we
read. Thus, we can safely perform multiple operations at a time, in parallel,
from unrelated coroutines, with no explicit sequencing in user code. Without
this guarantee, we would have to explicitly track the order in which operations
are performed, or, more easily, lock the underlying state so that we only
perform one operation at a time, reducing parallelism.

Our object-oriented style also gives us effect handlers which are not based on a
stack discipline.  We don't need to be concerned about computations being
performed in or out of the scope of handlers.  Effect handlers are simply
regular garbage collected objects: An effect handler stays alive as long as
there is something with a reference to it.

We also get an object-capability-style effect system for free.  Since we don't
rely on an implicit global event loop, there are no implicit global asynchronous
effects.  To allow a function to perform an asynchronous effect, we pass it (as
a normal argument) the object that implements that effect. The type of an
effectful function is simply a regular function type, accepting one or more
objects with which it can perform effects.[2]

[0]: If you aren't familiar with delimited continuations or shift/reset,
read this tutorial:
http://pllab.is.ocha.ac.jp/~asai/cw2011tutorial/main-e.pdf

[1]: Using delimited continuations to pass callbacks is a well known technique;
here's one post about it: 
http://www.gregrosenblatt.com/writing/reinvert-control-delim-cont.html

[2]: Since we can close over effect handlers (they're regular objects), a single
object or function might abstract over multiple effects. Is this a bad thing?
Some say yes, but it seems like a pretty normal form of abstraction to me.

"""
from dneio.core import shift, reset, Continuation, is_running_directly_under_trio
from dneio.concur import RequestQueue, Event, Future, make_n_in_parallel, run_all
