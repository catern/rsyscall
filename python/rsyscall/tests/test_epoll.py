from rsyscall.epoll import EpollEvent, epoll_create, epoll_ctl_add, epoll_ctl_mod, epoll_ctl_del, epoll_wait, EPOLL_CLOEXEC
import unittest
import os

class TestEpoll(unittest.TestCase):
    def test_create(self):
        epfd = epoll_create(EPOLL_CLOEXEC)
        os.close(epfd)

    def test_add(self):
        epfd = epoll_create(EPOLL_CLOEXEC)
        epoll_ctl_add(epfd, 2, EpollEvent.make(0))
        os.close(epfd)

    def test_mod(self):
        epfd = epoll_create(EPOLL_CLOEXEC)
        event = EpollEvent.make(0)
        epoll_ctl_add(epfd, 2, EpollEvent.make(0, in_=True))
        epoll_ctl_mod(epfd, 2, EpollEvent.make(0, out=True))
        os.close(epfd)

    def test_del(self):
        epfd = epoll_create(EPOLL_CLOEXEC)
        epoll_ctl_add(epfd, 2, EpollEvent.make(0))
        epoll_ctl_del(epfd, 2)
        os.close(epfd)

    def test_wait(self):
        epfd = epoll_create(EPOLL_CLOEXEC)
        epoll_ctl_add(epfd, 2, EpollEvent.make(42, out=True))
        events = epoll_wait(epfd, 1, 0)
        os.close(epfd)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].data, 42)
        self.assertTrue(events[0].out)

if __name__ == '__main__':
    import unittest
    unittest.main()
