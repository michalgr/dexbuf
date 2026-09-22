"""Dalvik bytecode type and method descriptor conversion and parsing utilities.

See https://source.android.com/docs/core/runtime/dex-format#type-descriptor
"""

from collections.abc import Sequence

__all__ = [
    "descriptor_to_type_name",
    "format_method_descriptor",
    "parse_method_descriptor",
    "type_name_to_descriptor",
]

_PRIMITIVE_TO_DESCRIPTOR: dict[str, str] = {
    "boolean": "Z",
    "byte": "B",
    "short": "S",
    "char": "C",
    "int": "I",
    "long": "J",
    "float": "F",
    "double": "D",
    "void": "V",
}

_DESCRIPTOR_TO_PRIMITIVE: dict[str, str] = {v: k for k, v in _PRIMITIVE_TO_DESCRIPTOR.items()}

_ILLEGAL_TYPE_NAME_CHARS: set[str] = set(";/[]()<> \t\n\r")
_ILLEGAL_DESCRIPTOR_CHARS: set[str] = set(".[]()<> \t\n\r")


def _parse_single_descriptor(descriptor: str, start: int = 0) -> tuple[str, int]:
    """Parse a single type descriptor starting at `start` in `descriptor`.

    Returns a tuple of (parsed_descriptor_str, end_index).
    Raises ValueError if descriptor is invalid.
    """
    if start >= len(descriptor):
        raise ValueError("Unexpected end of descriptor")

    idx = start
    dim = 0
    while idx < len(descriptor) and descriptor[idx] == "[":
        dim += 1
        idx += 1

    if idx >= len(descriptor):
        raise ValueError("Truncated array descriptor")

    ch = descriptor[idx]
    if ch in _DESCRIPTOR_TO_PRIMITIVE:
        if ch == "V" and dim > 0:
            raise ValueError("void cannot be an array element type")
        return descriptor[start : idx + 1], idx + 1
    elif ch == "L":
        end = descriptor.find(";", idx)
        if end == -1:
            raise ValueError("Unterminated class descriptor")
        class_body = descriptor[idx + 1 : end]
        if not class_body:
            raise ValueError("Empty class name in descriptor")
        if any(c in _ILLEGAL_DESCRIPTOR_CHARS for c in class_body):
            raise ValueError(f"Invalid character in class descriptor: {class_body!r}")
        parts = class_body.split("/")
        if not all(parts):
            raise ValueError(f"Invalid class descriptor format: {descriptor!r}")
        return descriptor[start : end + 1], end + 1
    else:
        raise ValueError(f"Invalid type descriptor character {ch!r} in {descriptor!r}")


def descriptor_to_type_name(descriptor: str) -> str:
    """Convert a Dalvik type descriptor to a canonical Java type name.

    See https://source.android.com/docs/core/runtime/dex-format#type-descriptor

    Args:
        descriptor: The Dalvik descriptor string (e.g. "I", "Ljava/lang/String;", "[[I").

    Returns:
        The canonical Java type name (e.g. "int", "java.lang.String", "int[][]").

    Raises:
        ValueError: If descriptor is empty or malformed.
    """
    if not isinstance(descriptor, str) or not descriptor:
        raise ValueError("Descriptor must be a non-empty string")

    parsed, end_idx = _parse_single_descriptor(descriptor, 0)
    if end_idx != len(descriptor):
        raise ValueError(f"Trailing characters in descriptor: {descriptor!r}")

    dim = 0
    while parsed[dim] == "[":
        dim += 1

    base_desc = parsed[dim:]
    if base_desc in _DESCRIPTOR_TO_PRIMITIVE:
        base_name = _DESCRIPTOR_TO_PRIMITIVE[base_desc]
    else:
        base_name = base_desc[1:-1].replace("/", ".")

    return base_name + "[]" * dim


def type_name_to_descriptor(name: str) -> str:
    """Convert a canonical Java type name to a Dalvik type descriptor.

    See https://source.android.com/docs/core/runtime/dex-format#type-descriptor

    Args:
        name: The Java type name (e.g. "int", "java.lang.String", "int[][]").

    Returns:
        The Dalvik type descriptor (e.g. "I", "Ljava/lang/String;", "[[I").

    Raises:
        ValueError: If name is empty or malformed.
    """
    if not isinstance(name, str) or not name:
        raise ValueError("Type name must be a non-empty string")

    dim = 0
    base_name = name
    while base_name.endswith("[]"):
        base_name = base_name[:-2]
        dim += 1

    if not base_name:
        raise ValueError(f"Invalid type name: {name!r}")

    if any(c in _ILLEGAL_TYPE_NAME_CHARS for c in base_name):
        raise ValueError(f"Invalid character in type name: {name!r}")

    if base_name == "void" and dim > 0:
        raise ValueError("void cannot be an array element type")

    if base_name in _PRIMITIVE_TO_DESCRIPTOR:
        base_desc = _PRIMITIVE_TO_DESCRIPTOR[base_name]
    else:
        parts = base_name.split(".")
        if not all(parts):
            raise ValueError(f"Invalid type name format: {name!r}")
        class_path = base_name.replace(".", "/")
        base_desc = f"L{class_path};"

    return "[" * dim + base_desc


def parse_method_descriptor(descriptor: str) -> tuple[tuple[str, ...], str]:
    """Parse a Dalvik method descriptor into parameter and return descriptors.

    See https://source.android.com/docs/core/runtime/dex-format#shorty-descriptor

    Args:
        descriptor: Method descriptor string (e.g. "(ILjava/lang/String;)V").

    Returns:
        A tuple of ((param_descriptor_1, param_descriptor_2, ...), return_descriptor).

    Raises:
        ValueError: If descriptor format is invalid.
    """
    if not isinstance(descriptor, str) or not descriptor.startswith("("):
        raise ValueError("Method descriptor must start with '('")

    close_idx = descriptor.find(")")
    if close_idx == -1:
        raise ValueError("Method descriptor missing ')'")

    if descriptor.rfind(")") != close_idx or "(" in descriptor[1:]:
        raise ValueError("Malformed parenthesis in method descriptor")

    param_str = descriptor[1:close_idx]
    return_str = descriptor[close_idx + 1 :]

    params: list[str] = []
    idx = 0
    while idx < len(param_str):
        param_desc, next_idx = _parse_single_descriptor(param_str, idx)
        if param_desc == "V":
            raise ValueError("Method parameter cannot be void ('V')")
        params.append(param_desc)
        idx = next_idx

    ret_desc, ret_next_idx = _parse_single_descriptor(return_str, 0)
    if ret_next_idx != len(return_str):
        raise ValueError("Trailing characters after return descriptor")

    return (tuple(params), ret_desc)


def format_method_descriptor(param_descriptors: Sequence[str], return_descriptor: str) -> str:
    """Format parameter descriptors and a return descriptor into a method descriptor.

    See https://source.android.com/docs/core/runtime/dex-format#shorty-descriptor

    Args:
        param_descriptors: Sequence of parameter type descriptors.
        return_descriptor: Return type descriptor.

    Returns:
        Formatted method descriptor string (e.g. "(ILjava/lang/String;)V").

    Raises:
        ValueError: If any parameter is void or if any descriptor is malformed.
    """
    valid_params: list[str] = []
    for p in param_descriptors:
        if not isinstance(p, str):
            raise ValueError("Parameter descriptor must be a string")
        parsed, end_idx = _parse_single_descriptor(p, 0)
        if end_idx != len(p):
            raise ValueError(f"Invalid parameter descriptor: {p!r}")
        if parsed == "V":
            raise ValueError("Method parameter descriptor cannot be void ('V')")
        valid_params.append(parsed)

    if not isinstance(return_descriptor, str):
        raise ValueError("Return descriptor must be a string")
    parsed_ret, ret_end_idx = _parse_single_descriptor(return_descriptor, 0)
    if ret_end_idx != len(return_descriptor):
        raise ValueError(f"Invalid return descriptor: {return_descriptor!r}")

    return f"({''.join(valid_params)}){parsed_ret}"
