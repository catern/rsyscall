from setuptools import setup, find_packages

setup(name='rsyscall',
      version='0.0.3',
      description='A library for making system calls remotely, through another process, which may be located on a remote host',
      classifiers=[
          "Programming Language :: Python :: 3",
          "License :: OSI Approved :: MIT License",
          "Operating System :: POSIX :: Linux",
      ],
      keywords='linux syscall distributed',
      url='https://github.com/catern/rsyscall',
      author='catern',
      author_email='sbaugh@catern.com',
      license='MIT',
      cffi_modules=["ffibuilder.py:ffibuilder"],
      packages=find_packages(),
      nixdeps={'rsyscall._nixdeps': ['nix', 'librsyscall', 'openssh', 'coreutils']},
      include_package_data=True,
)
