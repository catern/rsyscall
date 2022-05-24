from __future__ import annotations

from rsyscall.tests.trio_test_case import TrioTestCase

from rsyscall.sys.mman import PROT, MAP, MADV

class TestMisc(TrioTestCase):
    async def test_madvise(self) -> None:
        mapping = await self.process.task.mmap(4096, PROT.READ|PROT.WRITE, MAP.SHARED)
        await mapping.madvise(MADV.REMOVE)
        await mapping.munmap()
