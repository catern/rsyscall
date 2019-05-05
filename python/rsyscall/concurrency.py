import trio
import contextlib
from dataclasses import dataclass
import typing as t

@dataclass
class OneAtATime:
    running: t.Optional[trio.Event] = None

    @contextlib.asynccontextmanager
    async def needs_run(self) -> t.AsyncGenerator[bool, None]:
        if self.running is not None:
            yield False
            await self.running.wait()
        else:
            running = trio.Event()
            self.running = running
            try:
                yield True
            finally:
                self.running = None
                running.set()
