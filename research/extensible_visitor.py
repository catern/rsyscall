from __future__ import annotations
import typing as t
import abc
T = t.TypeVar('T')

#### Dog is one variant
class DogImpl:
    def bark(self) -> str:
        return "bark bark bark"

    def accept(self, visitor: DogVisitor[T]) -> T:
        return visitor.visit_dog(self)

class DogVisitor(t.Generic[T]):
    # The visitor method doesn't have to have a different name per variant, but
    # overloading is a hassle in Python, so we use different names for this example.
    @abc.abstractmethod
    def visit_dog(self, dog: DogImpl) -> T: ...

#### Cat is another variant
class CatImpl:
    def lives(self) -> int:
        return 9

    def accept(self, visitor: CatVisitor[T]) -> T:
        return visitor.visit_cat(self)

class CatVisitor(t.Generic[T]):
    @abc.abstractmethod
    def visit_cat(self, cat: CatImpl) -> T: ...

#### Mammal can be a Cat or a Dog
class Mammal:
    @abc.abstractmethod
    def accept(self, visitor: MammalVisitor[T]) -> T: ...

class MammalVisitor(t.Generic[T], DogVisitor[T], CatVisitor[T]):
    pass

# "constructors" for the Mammal variant
class MammalCat(CatImpl, Mammal):
    pass

class MammalDog(DogImpl, Mammal):
    pass

# we can write normal programs using the visitor pattern
class Petter(MammalVisitor[str]):
    def visit_cat(self, cat: CatImpl) -> str:
        return f"petting this cat with {cat.lives()} lives"

    def visit_dog(self, dog: DogImpl) -> str:
        return f"petting this dog; it says {dog.bark()}"

def pet_mammals(mammals: t.List[Mammal]) -> None:
    petter = Petter()
    for mammal in mammals:
        print(mammal.accept(petter))

my_mammals: t.List[Mammal] = [MammalDog(), MammalCat(), MammalDog()]

pet_mammals(my_mammals)

#### Fish is a third new variant
class FishImpl:
    def weight(self) -> float:
        return 2.334

    def accept(self, visitor: FishVisitor[T]) -> T:
        return visitor.visit_fish(self)

class FishVisitor(t.Generic[T]):
    @abc.abstractmethod
    def visit_fish(self, fish: FishImpl) -> T: ...

#### Animal can be Cat, Dog, or Fish
class Animal:
    @abc.abstractmethod
    def accept(self, visitor: AnimalVisitor[T]) -> T: ...

class AnimalVisitor(t.Generic[T], MammalVisitor[T], FishVisitor[T]):
    pass

class AnimalCat(CatImpl, Animal):
    pass

class AnimalDog(DogImpl, Animal):
    pass

class AnimalFish(FishImpl, Animal):
    pass

# our old programs still work;
pet_mammals(my_mammals)
# but we can write new programs too that work on the new expanded class
class Weigher(AnimalVisitor[float]):
    def visit_cat(self, cat: CatImpl) -> float:
        return float(cat.lives())

    def visit_dog(self, dog: DogImpl) -> float:
        # estimate weight by size of bark
        return float(len(dog.bark()))

    def visit_fish(self, fish: FishImpl) -> float:
        return fish.weight()

def total_weight(animals: t.List[Animal]) -> float:
    weigher = Weigher()
    return sum(animal.accept(weigher) for animal in animals)

these_animals: t.List[Animal] = [AnimalDog(), AnimalFish(), AnimalCat()]

print("these animals weigh", sum(animal.accept(Weigher()) for animal in these_animals))
# and our new programs work on the smaller old classes
print("my mammals weigh", sum(animal.accept(Weigher()) for animal in my_mammals))
