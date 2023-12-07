from re import match

from dataclasses import dataclass
import re
from sys import stderr
from typing import Iterable, TextIO


Key = tuple[str, str, str]


def err(*args, **kwargs) -> None:
    print(*args, **kwargs, file=stderr)


class RuleConflictError(Exception):
    pass


@dataclass
class NameTransition:
    rule: str
    line: int
    src: str
    tgt: str
    cls: str
    name: str
    otype: str

    def key(self) -> Key:
        return self.src, self.tgt, self.cls

    def value(self) -> tuple[str, str]:
        return self.name, self.otype

    def cil(self, match_type: str | None = None) -> str:
        if match_type is not None:
            return f"(typetransition {self.src} {self.tgt} {self.cls} " \
                   f"\"{self.name}\" {match_type} {self.otype})"
        return f"(typetransition {self.src} {self.tgt} {self.cls} " \
               f"\"{self.name}\" {self.otype})"

    def __str__(self) -> str:
        return self.cil()


class Node:
    def __init__(self) -> None:
        self.letters: dict[str, Node] = dict()
        self.child_types: set[str] = set()
        self.otype: str | None = None

    def insert(self, name: str, otype: str) -> set[str]:
        if len(name) == 0:
            if self.otype is not None:
                raise RuleConflictError()
            self.otype = otype
            self.child_types.add(self.otype)
        else:
            start, suffix = name[0], name[1:]
            if start not in self.letters:
                self.letters[start] = Node()
            self.child_types.update(self.letters[start].insert(suffix, otype))
        return self.child_types

    def get_rules(self, prefix: str = "") -> Iterable[tuple[str, bool, str]]:
        child_types = self.child_types.copy()
        if self.otype is not None and prefix != "":
            if len(child_types) == 1 and len(self.letters) > 0:
                yield prefix, True, self.otype
                return
            child_types.remove(self.otype)
            yield prefix, False, self.otype

        if len(child_types) == 1 and len(self.letters) > 1 and prefix != "":
            yield prefix, True, next(iter(child_types))
            return

        if len(self.letters) == 0:
            return

        child_rules: dict[str, list[tuple[str, bool, str]]] = dict()
        for letter, node in self.letters.items():
            for name, is_prefix, otype in node.get_rules(prefix + letter):
                child_rules.setdefault(otype, [])
                child_rules[otype].append((name, is_prefix, otype))
        sorted_child_rules = sorted(child_rules.items(),
                                    key=lambda di: -len(di[1]))

        opt_i = -1
        for i, (_, subrules) in enumerate(sorted_child_rules):
            if len(subrules) < 2 or prefix == "":
                continue
            safe = True
            for j, (_, check_subrules) in enumerate(sorted_child_rules):
                if i == j:
                    continue
                for subprefix, _, _, in subrules:
                    for check_subprefix, _, _ in check_subrules:
                        if subprefix.startswith(check_subprefix):
                            safe = False
            if safe:
                opt_i = i
                break

        if opt_i >= 0:
            yield prefix, True, sorted_child_rules[opt_i][0]
        for i, (_, subrules) in enumerate(sorted_child_rules):
            if i == opt_i:
                continue
            for subprefix, is_subprefix, subotype in subrules:
                yield subprefix, is_subprefix, subotype

        # opt_i = -1
        # for i, rules in enumerate()


    def export_dot(self, file: str | TextIO = "tree.dot", root: bool = True) \
            -> None:
        close_file = isinstance(file, str)
        if close_file := isinstance(file, str):
            file = open(file, "w")
        if root:
            file.write("digraph T {\n")

        label = self.otype if self.otype is not None else ''
        file.write(f"node [label=\"{label}\"] {id(self)};\n")
        for letter, child in self.letters.items():
            child.export_dot(file, False)
            file.write(f"{id(self)} -> {id(child)} [label=\"{letter}\"];\n")

        if root:
            file.write("}\n")
        if close_file:
            file.close()


def parse(rule: str, line: int) -> NameTransition | None:
    m = match(r"""^\(
            typetransition\s
            (?P<src>\S+)\s
            (?P<tgt>\S+)\s
            (?P<cls>\S+)\s
            (?:\"(?P<nameq>\S+)\"|(?P<name>\S+))\s
            (?P<otype>\S+)
            \)$""", rule, re.VERBOSE)
    return None if m is None else NameTransition(
        rule,
        line,
        m.group("src"),
        m.group("tgt"),
        m.group("cls"),
        m.group("name") if m.group("name") is not None else m.group("nameq"),
        m.group("otype"),
    )


def get_match(name_transition: NameTransition,
              exact: dict[Key, list[NameTransition]],
              prefix: dict[Key, list[NameTransition]],
              suffix: dict[Key, list[NameTransition]]) -> str | None:
    exact_possibles = iter(rule.otype
                           for rule
                           in exact.get(name_transition.key(), [])
                           if rule.name == name_transition.name)
    try:
        otype = next(exact_possibles)
        try:
            next(exact_possibles)
            err(f"Multiple ({len(list(exact_possibles)) + 2}) "
                f"for {name_transition=}")
            return None
        except StopIteration:
            return otype
    except StopIteration:
        pass
    for l in range(len(name_transition.name), 0, -1):
        try:
            return next(rule.otype
                        for rule
                        in prefix.get(name_transition.key(), [])
                        if rule.name == name_transition.name[0:l])
        except StopIteration:
            pass
    for l in range(len(name_transition.name), 0, -1):
        try:
            return next(rule.otype
                        for rule
                        in suffix.get(name_transition.key(), [])
                        if rule.name == name_transition.name[l - 1:])
        except StopIteration:
            pass
    return None


def main() -> int:
    # (src, tgt, cls) -> (name, otype)
    name_transitions: list[NameTransition] = []
    linen = 1
    err("Reading rules...")
    try:
        while True:
            line = input()
            rule = parse(line, linen)
            if rule is not None:
                name_transitions.append(rule)
            else:
                print(line)
            linen += 1
    except EOFError:
        pass

    err("Building prefix tries...")
    name_transitions_tree: dict[Key, Node] = dict()
    for name_transition in name_transitions:
        try:
            if name_transition.key() not in name_transitions_tree:
                name_transitions_tree[name_transition.key()] = Node()
            name_transitions_tree[name_transition.key()].insert(
                    name_transition.name, name_transition.otype,
            )
        except RuleConflictError:
            err(f"Duplicate rule at {name_transition.line}:{name_transition.rule}")
            return 1

    err("Extracting prefix rules...")
    exact: dict[Key, list[NameTransition]] = dict()
    prefix: dict[Key, list[NameTransition]] = dict()
    for key, node in name_transitions_tree.items():
        exact.setdefault(key, [])
        prefix.setdefault(key, [])
        for name, is_prefix, otype in node.get_rules():
            if is_prefix:
                prefix[key].append(NameTransition("", -1, *key, name, otype))
            else:
                exact[key].append(NameTransition("", -1, *key, name, otype))

    # err("Building suffix tries...")
    # suffix_name_transition_tree: dict[Key, Node] = dict()
    # for key, name_transitions in exact.items():
    #     if key not in suffix_name_transition_tree:
    #         suffix_name_transition_tree[key] = Node()
    #     for name_transition in name_transitions:
    #         suffix_name_transition_tree[key].insert(name_transition.name[::-1], name_transition.otype)

    # err("Extracting suffix rules...")
    # exact = dict()
    suffix: dict[Key, list[NameTransition]] = dict()
    # for key, node in suffix_name_transition_tree.items():
    #     if key not in exact:
    #         exact[key] = []
    #     if key not in suffix:
    #         suffix[key] = []
    #     for name, is_suffix, otype in node.get_rules():
    #         if is_suffix:
    #             suffix[key].append(NameTransition("", -1, *key, name[::-1], otype))
    #         else:
    #             exact[key].append(NameTransition("", -1, *key, name[::-1], otype))

    err("Verifying rules...")
    for name_transition in name_transitions:
        otype = get_match(name_transition, exact, prefix, suffix)
        if otype != name_transition.otype:
            err(f"Invalid {otype=} for {name_transition}")

    err(f"Outputing rules...")
    exactc, prefixc, suffixc = 0, 0, 0
    for exact_rules in exact.values():
        for exact_rule in exact_rules:
            print(exact_rule.cil())
            exactc += 1
    for prefix_rules in prefix.values():
        for prefix_rule in prefix_rules:
            print(prefix_rule.cil("prefix"))
            prefixc += 1
    for suffix_rules in suffix.values():
        for suffix_rule in suffix_rules:
            print(suffix_rule.cil("suffix"))
            suffixc += 1
    err(f"{exactc=} {prefixc=} {suffixc=}")

    return 0


if __name__ == "__main__":
    exit(main())
