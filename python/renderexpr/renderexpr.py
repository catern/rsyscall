from __future__ import annotations
from dataclasses import dataclass
import collections
import graphviz
import typing as t
import types
import copy
import functools

class Globals(dict):
    def __init__(self, graph: Graph, *args, **kwargs) -> None:
        self.graph = graph
        super().__init__(*args, **kwargs)

    def __missing__(self, name: str) -> Symbol:
        sym = Symbol(self.graph, name)
        self[name] = sym
        return sym

@dataclass
class Graph:
    dot: graphviz.Digraph
    name_counts: collections.Counter

    @classmethod
    def make(cls) -> Graph:
        return cls(graphviz.Digraph(), collections.Counter())

    def generate_node(self, name: str) -> Node:
        if name in self.name_counts:
            node = Node(name + str(self.name_counts[name]))
        else:
            node = Node(name)
        self.name_counts[name] += 1
        self.dot.node(node.name, label=name)
        return node

    def symbolize(
            self,
            func: types.FunctionType,
            supplemental_globals: t.Dict[str, t.Any],
    ) -> types.FunctionType:
        globals = Globals(self, **supplemental_globals)
        new_func = types.FunctionType(
            func.__code__, globals, name=func.__name__,
            argdefs=func.__defaults__, closure=func.__closure__,
        )
        new_func = functools.update_wrapper(new_func, func)
        new_func.__kwdefaults__ = copy.copy(func.__kwdefaults__)
        return new_func

@dataclass
class Node:
    name: str

    def __await__(self) -> Node:
        return self
        yield # to make this an iterator

@dataclass
class Symbol:
    __graph: Graph
    __name: str

    def __call__(self, *args, **kwargs) -> Node:
        deps: t.List[Node] = []
        print("call", self.__name, args)
        funcnode = self.__graph.generate_node(self.__name)
        if kwargs:
            raise Exception("TODO")
        for arg in args:
            if isinstance(arg, Symbol):
                node = self.__graph.generate_node(arg.__name)
            elif isinstance(arg, Node):
                node = arg
            else:
                # TODO: how to inline these arguments into the node?
                node = self.__graph.generate_node(str(arg))
            self.__graph.dot.edge(funcnode.name, node.name)
        return funcnode

    def __getattr__(self, attr: str) -> Symbol:
        return Symbol(self.__graph, self.__name + "." + attr)
