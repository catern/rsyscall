import setuptools
import os

class NixDeps(setuptools.Command):
    def initialize_options(self) -> None:
        self.nix_deps = None

    def finalize_options(self) -> None:
        pass

    def run(self) -> None:
        for dep in self.nix_deps:
            path = os.environ[dep]
            # write JSON to place
            # h M m M m M m.
            # what place tho?
            # I want to make a package which provides a new setuptools coomand, which, when used, generates some data files for a package at build time; then I want that package to be able to load those data files using helper functions from that same package
            # what I'm not sure about is, where should I put these data files so that they can be loaded at runtime? should I try and stick them inside the user package? or somewhere else
            pass
