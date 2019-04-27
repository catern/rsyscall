from dataclasses import dataclass

@dataclass
class Pointer:
    address: int

    def __add__(self, other: int) -> 'Pointer':
        return Pointer(self.address + other)

    def __sub__(self, other: int) -> 'Pointer':
        return Pointer(self.address - other)

    def __str__(self) -> str:
        return f"Pointer({hex(self.address)})"

    def __repr__(self) -> str:
        return str(self)

    def __int__(self) -> int:
        return self.address
