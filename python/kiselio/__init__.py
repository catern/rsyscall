"""Concurrency based on shift/reset and object-oriented effect handlers

Our core insight is this: Traditional callback-based concurrency systems, where
we pass around objects and call methods on those objects to register callbacks,
can be elevated to full-featured direct-style concurrency by using delimited
continuations[0].

A traditional callback-based concurrency system has a major advantage: Rather
than yield to a central event loop as in other concurrency systems, we can
register a callback on any object, which is then responsible for calling back
into us and running us again. That object in turn can register callbacks on
other objects, until it reaches some object which performs a primitive blocking
operation, blocking in the kernel right then and there. In such a system, there
is no central "event loop" or any concurrency primitives beyond the function
call.

However, such a system is awkward to program with, because we must program in
continuation-passing-style, constantly performing manual stack ripping. Like so:

```
file.read_cb(lambda data: more_work(data))
```

But, with a delimited continuation operator such as shift/reset, we can register
*our current continuation* as a callback. We are then able to program in
stackful direct style, with regular, straight-line code, with "blocking
operations" implemented as simply shifting into some object accepting callbacks.
Like so:

```
data = await shift(file.read_cb)
more_work(data)
```

This gives us effect handlers which are not based on a stack discipline. We
don't need to be concerned about computations being performed in or out of the
scope of handlers. Effect handlers are simply regular garbage collected objects:
An effect handler stays alive as long as there is something with a reference to
it.

We also get a corresponding effect system for free, in an object-capability
style.  Since there is no global event loop, there are no global effects.  A
function which performs effects then must have the object with which it performs
the effect, passed as a normal argument. The type of an effectful function is
simply a regular function type, accepting some objects with which it can perform
an effect.

In some sense, we lose some specificity of typing, because we can close over
effect handlers - they're regular objects. So a single object or function may be
passed which abstracts over multiple effects. But this is a desirable and
natural form of abstraction - and anyway, it's the unavoidable result of
programming in a type theory based on classical logic with double negation
elimination.

We also get the intutitive ordering semantics of callback-based concurrency
systems.  In a callback system, an object can guarantee that when callbacks are
registered in a certain order, the underlying operations are performed in that
order, and the registered callbacks are called in that same order.  `shift`
returns immediately and synchronously when a continuation is resumed, so these
guarantees also apply for coroutines.  This can allow for simpler programming;
for example, stateful bookkeeping can be updated for each operation without
concerns about events being reordered, and concurrent manipulation of a single
underlying object can often be written naively, with no locking. Information
about the order of events is implicit in the order that code executes, rather
than explicitly tracked through some additional mechanism requiring cooperation
from individual objects.  We are not aware of any other system providing
direct-style concurrency which provides this guarantee.

[0]: If you aren't familiar with delimited continuations or shift/reset,
read this tutorial:
http://pllab.is.ocha.ac.jp/~asai/cw2011tutorial/main-e.pdf

"""
from kiselio.core import shift, reset, Continuation, is_running_directly_under_trio
from kiselio.concur import RequestQueue, Event, Future, make_n_in_parallel, run_all
