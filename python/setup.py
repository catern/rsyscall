from setuptools import setup

setup(name='rsyscall',
      version='0.1.0',
      description='A library for making system calls remotely, through another process, which may be located on a remote host',
      classifiers=[
          "License :: OSI Approved :: MIT License",
          "Operating System :: POSIX :: Linux",
      ],
      keywords='linux syscall distributed',
      url='https://github.com/catern/rsyscall',
      author='catern',
      author_email='sbaugh@catern.com',
      license='MIT',
      cffi_modules=["ffibuilder.py:ffibuilder"],
      packages=['rsyscall', 'rsyscall.tests'])
