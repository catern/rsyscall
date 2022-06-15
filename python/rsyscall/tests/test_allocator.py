from __future__ import annotations

from rsyscall.tests.trio_test_case import TrioTestCase
from rsyscall.memory.allocator import BumpAllocator, OutOfSpaceError

class TestMisc(TrioTestCase):
    async def test_madvise(self) -> None:
        size = 4096
        allocator = await BumpAllocator.make(self.process.task, size)
        mapping, first = await allocator.malloc(size//2, 1)
        _, second = await allocator.malloc(size//2, 1)
        with self.assertRaises(OutOfSpaceError):
            await allocator.malloc(size//2, 1)
        first.free(mapping)
        # this only works because the free happens immediately on the local process,
        # instead of waiting for the madvise response to come back,
        # usually free is asynchronous
        _, third = await allocator.malloc(size//2, 1)
