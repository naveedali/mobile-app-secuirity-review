#!/usr/bin/env python3
"""Flag direct Android Log messages that reference likely sensitive values."""

import argparse
import json
from pathlib import Path
import re
import sys
from typing import NamedTuple

IDENTIFIER = re.compile(r"[^\W\d]\w*")
BLOCK_MARKER = re.compile(r"/\*|\*/")
PLAIN_TOKEN = re.compile(r"`[^`\n]*`|'(?:\\.|[^'\\\n])*'|[^\W\d]\w*|\s+|.", re.DOTALL)
ANDROID_LOG = ["android", ".", "util", ".", "Log"]
METHODS = {"v", "d", "i", "w", "e", "wtf"}
SENSITIVE_NAMES = {
    "accesstoken", "refreshtoken", "authtoken", "sessiontoken",
    "password", "passcode", "apikey", "clientsecret", "authorization",
}


class Token(NamedTuple):
    text: str
    line: int
    references: tuple = ()


def is_sensitive(name):
    return name.replace("_", "").casefold() in SENSITIVE_NAMES


def read_piece(source, start):
    """Read one Kotlin lexical piece, including strings and nested comments."""
    if source.startswith("//", start):
        end = source.find("\n", start)
        return (len(source) if end < 0 else end), (), True
    if source.startswith("/*", start):
        depth = 1
        for match in BLOCK_MARKER.finditer(source, start + 2):
            depth += 1 if match.group() == "/*" else -1
            if depth == 0:
                return match.end(), (), True
        raise ValueError("Unterminated block comment.")

    if source[start] != '"':
        match = PLAIN_TOKEN.match(source, start)
        return match.end(), (), match.group().isspace()

    delimiter = '"""' if source.startswith('"""', start) else '"'
    cursor = start + len(delimiter)
    references = []
    while cursor < len(source):
        if source.startswith(delimiter, cursor):
            return cursor + len(delimiter), tuple(references), False
        if delimiter == '"' and source[cursor] == "\\":
            cursor += 2
            continue
        if source.startswith('${', cursor):
            expression = cursor + 2
            cursor = expression
            depth = 1
            while cursor < len(source) and depth:
                if source[cursor] == "{":
                    depth += 1
                elif source[cursor] == "}":
                    depth -= 1
                if not depth:
                    name = source[expression:cursor].strip()
                    if IDENTIFIER.fullmatch(name):
                        references.append(name)
                    cursor += 1
                    break
                cursor, _, _ = read_piece(source, cursor)
            continue
        if source[cursor] == "$":
            match = IDENTIFIER.match(source, cursor + 1)
            if match:
                references.append(match.group())
                cursor = match.end()
                continue
        cursor += 1
    raise ValueError("Unterminated string or template.")


def tokenize(source):
    cursor = 0
    line = 1
    while cursor < len(source):
        end, references, ignored = read_piece(source, cursor)
        text = source[cursor:end]
        if not ignored:
            yield Token(text, line, references)
        line += text.count("\n")
        cursor = end


def message_token(tokens, start):
    """Read the second argument when it consists of a single token."""
    expected = []
    closes = {"(": ")", "[": "]", "{": "}"}
    for index in range(start, len(tokens)):
        text = tokens[index]
        if text == "," and not expected:
            message = index + 1
            if tokens[message + 1:message + 2] in ([","], [")"]):
                return message
            return None
        if text in closes:
            expected.append(closes[text])
        elif text in closes.values():
            if not expected or text != expected.pop():
                return None
    return None


def inspect(source, path):
    pieces = list(tokenize(source))
    tokens = [piece.text for piece in pieces]
    imported = any(
        tokens[index:index + 6] == ["import", *ANDROID_LOG]
        and tokens[index + 6:index + 7] != ["as"]
        and tokens[index + 6:index + 7] != ["."]
        for index, token in enumerate(tokens)
        if token == "import"
    )
    findings = []
    for index, token in enumerate(tokens):
        if index and tokens[index - 1] in {".", "::"}:
            continue
        if tokens[index:index + 5] == ANDROID_LOG:
            end = index + 5
        elif token == "Log" and imported:
            end = index + 1
        else:
            continue
        if end + 2 >= len(tokens):
            continue
        dot, method, opening = tokens[end:end + 3]
        if dot != "." or method not in METHODS or opening != "(":
            continue
        message = message_token(tokens, end + 3)
        if message is None:
            continue
        piece = pieces[message]
        if is_sensitive(piece.text) or any(map(is_sensitive, piece.references)):
            findings.append({
                "rule_id": "MSR007",
                "status": "needs-review",
                "path": str(path),
                "line": pieces[index].line,
                "sink": "android.util.Log." + method,
                "message": "The log message directly references a sensitive-looking name.",
            })
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path, metavar="FILE.kt")
    args = parser.parse_args(argv)
    findings = []
    errors = []
    for path in dict.fromkeys(args.files):
        try:
            if path.suffix != ".kt" or not path.is_file():
                raise ValueError("Expected a regular Kotlin .kt source file.")
            findings.extend(inspect(path.read_text(encoding="utf-8-sig"), path))
        except (OSError, UnicodeError):
            errors.append({"path": str(path), "message": "Could not read UTF-8 Kotlin source."})
        except RecursionError:
            errors.append({"path": str(path), "message": "String templates are nested too deeply."})
        except ValueError as error:
            errors.append({"path": str(path), "message": str(error)})
    print(json.dumps({
        "schema_version": "1.0",
        "completion": "incomplete" if errors else "completed-limited-checks",
        "inputs": [str(path) for path in dict.fromkeys(args.files)],
        "findings": findings,
        "errors": errors,
        "limitations": [
            "Lexical matching of direct Kotlin Android Log messages.",
            "Symbol resolution, data flow, and release behavior require separate review.",
        ],
    }, indent=2))
    if errors:
        return 2
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
