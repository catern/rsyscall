from setuptools import setup

# can we find the thing on the path? hm.
# no we want the references graph too. hm.
setup(name='rsyscall',
      version='0.1.0',
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
      packages=['rsyscall', 'rsyscall.tests', 'nixdeps', 'arepl', 'arepl.tests', 'rsysapps'],
      nix_deps={'rsyscall._nixdeps': ['miredo', 'nix', 'rsyscall', 'openssh', 'bash', 'coreutils', 'hello']},
      entry_points={
          'distutils.setup_keywords': [
              "nix_deps = nixdeps.setuptools:nix_deps",
          ],
      },
)
