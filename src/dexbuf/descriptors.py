"""Dalvik descriptor and Java type conversion utilities.

Refer to the Android DEX Format Specification for type and method descriptor syntax:
https://source.android.com/docs/core/runtime/dex-format
"""

from collections.abc import Iterable

# Mapping from primitive descriptor characters to canonical Java primitive type names.
PRIMITIVE_DESCRIPTOR_TO_NAME: dict[str, str] = {
    "Z": "boolean",
    "B": "byte",
    "S": "short",
    "C": "char",
    "I": "int",
    "J": "long",
    "F": "float",
    "D": "double",
    "V": "void",
}

# Mapping from canonical Java primitive type names to primitive descriptor characters.
PRIMITIVE_NAME_TO_DESCRIPTOR: dict[str, str] = {
    name: desc for desc, name in PRIMITIVE_DESCRIPTOR_TO_NAME.items()
}


def _is_valid_identifier_part(part: str) -> bool:
    """Check if a package/class name identifier component is valid in Java."""
    if not part or part[0].isdigit():
        return False
    for ch in part:
        if not (ch.isalnum() or ch in ("_", "$")):
            return False
    return True


def _parse_single_descriptor(
    descriptor: str, offset: int = 0, allow_void: bool = True
) -> tuple[str, int]:
    """Parse a single type descriptor from `descriptor` starting at `offset`.

    Returns a tuple of `(parsed_descriptor_str, next_offset)`.
    Raises `ValueError` if the descriptor is malformed or invalid.
    """
    if offset < 0 or offset >= len(descriptor):
        raise ValueError("Invalid offset or empty descriptor string")

    idx = offset
    while idx < len(descriptor) and descriptor[idx] == "[":
        idx += 1

    array_dims = idx - offset
    if idx >= len(descriptor):
        raise ValueError(f"Truncated array descriptor in {descriptor!r}")

    ch = descriptor[idx]
    if ch in PRIMITIVE_DESCRIPTOR_TO_NAME:
        if ch == "V" and (array_dims > 0 or not allow_void):
            raise ValueError(f"Invalid use of 'void' descriptor in {descriptor!r}")
        next_offset = idx + 1
        return descriptor[offset:next_offset], next_offset

    if ch == "L":
        end_idx = descriptor.find(";", idx + 1)
        if end_idx == -1:
            raise ValueError(f"Class descriptor missing terminating ';' in {descriptor!r}")

        internal_name = descriptor[idx + 1 : end_idx]
        if not internal_name:
            raise ValueError(f"Empty class name in descriptor {descriptor!r}")

        parts = internal_name.split("/")
        for part in parts:
            if not _is_valid_identifier_part(part):
                raise ValueError(f"Invalid class name component {part!r} in {descriptor!r}")

        next_offset = end_idx + 1
        return descriptor[offset:next_offset], next_offset

    raise ValueError(f"Invalid descriptor character {ch!r} in {descriptor!r}")


def descriptor_to_type_name(descriptor: str) -> str:
    """Convert a Dalvik bytecode type descriptor to a canonical Java type name.

    Examples:
        - "Z" -> "boolean"
        - "Ljava/lang/String;" -> "java.lang.String"
        - "[I" -> "int[]"
        - "[[Ljava/lang/String;" -> "java.lang.String[][]"

    See https://source.android.com/docs/core/runtime/dex-format for specification details.
    """
    if not isinstance(descriptor, str) or not descriptor:
        raise ValueError("Descriptor must be a non-empty string")

    parsed, end_offset = _parse_single_descriptor(descriptor, offset=0, allow_void=True)
    if end_offset != len(descriptor):
        raise ValueError(f"Trailing unparsed characters in descriptor {descriptor!r}")

    array_dims = 0
    while array_dims < len(parsed) and parsed[array_dims] == "[":
        array_dims += 1

    element_desc = parsed[array_dims:]
    if element_desc in PRIMITIVE_DESCRIPTOR_TO_NAME:
        base_name = PRIMITIVE_DESCRIPTOR_TO_NAME[element_desc]
    elif element_desc.startswith("L") and element_desc.endswith(";"):
        base_name = element_desc[1:-1].replace("/", ".")
    else:
        raise ValueError(f"Invalid element descriptor {element_desc!r}")

    return f"{base_name}{'[]' * array_dims}"


def type_name_to_descriptor(name: str) -> str:
    """Convert a canonical Java type name to a Dalvik bytecode type descriptor.

    Examples:
        - "int" -> "I"
        - "boolean" -> "Z"
        - "void" -> "V"
        - "com.example.MyClass" -> "Lcom/example/MyClass;"
        - "int[]" -> "[I"
        - "java.lang.String[][]" -> "[[Ljava/lang/String;"

    See https://source.android.com/docs/core/runtime/dex-format for specification details.
    """
    if not isinstance(name, str) or not name:
        raise ValueError("Type name must be a non-empty string")

    array_dims = 0
    curr = name
    while curr.endswith("[]"):
        array_dims += 1
        curr = curr[:-2]

    if not curr:
        raise ValueError(f"Invalid type name: {name!r}")

    if "[" in curr or "]" in curr:
        raise ValueError(f"Invalid array syntax in type name: {name!r}")

    if curr in PRIMITIVE_NAME_TO_DESCRIPTOR:
        if curr == "void" and array_dims > 0:
            raise ValueError(f"Array of void is not allowed: {name!r}")
        elem_desc = PRIMITIVE_NAME_TO_DESCRIPTOR[curr]
    else:
        parts = curr.split(".")
        for part in parts:
            if not _is_valid_identifier_part(part):
                raise ValueError(f"Invalid class name component {part!r} in {name!r}")
        elem_desc = f"L{curr.replace('.', '/')};"

    return f"{'[' * array_dims}{elem_desc}"


def parse_method_descriptor(descriptor: str) -> tuple[tuple[str, ...], str]:
    """Parse a Dalvik method descriptor into parameter descriptors and return descriptor.

    Example:
        parse_method_descriptor("(ILjava/lang/String;)V") -> (("I", "Ljava/lang/String;"), "V")

    See https://source.android.com/docs/core/runtime/dex-format for specification details.
    """
    if not isinstance(descriptor, str) or not descriptor.startswith("("):
        raise ValueError(f"Method descriptor must start with '(': {descriptor!r}")

    idx = 1
    params: list[str] = []
    while idx < len(descriptor) and descriptor[idx] != ")":
        param_desc, idx = _parse_single_descriptor(descriptor, offset=idx, allow_void=False)
        params.append(param_desc)

    if idx >= len(descriptor) or descriptor[idx] != ")":
        raise ValueError(f"Method descriptor missing ')' in {descriptor!r}")

    idx += 1
    return_str = descriptor[idx:]
    if not return_str:
        raise ValueError(f"Method descriptor missing return type in {descriptor!r}")

    return_desc, end_offset = _parse_single_descriptor(return_str, offset=0, allow_void=True)
    if end_offset != len(return_str):
        raise ValueError(f"Trailing unparsed characters in return descriptor {return_str!r}")

    return tuple(params), return_desc


def format_method_descriptor(param_descriptors: Iterable[str], return_descriptor: str) -> str:
    """Format parameter descriptors and return descriptor into a Dalvik method descriptor string.

    Example:
        format_method_descriptor(("I", "Ljava/lang/String;"), "V") -> "(ILjava/lang/String;)V"

    See https://source.android.com/docs/core/runtime/dex-format for specification details.
    """
    valid_params: list[str] = []
    for param in param_descriptors:
        if not isinstance(param, str):
            raise ValueError(f"Parameter descriptor must be a string, got {type(param).__name__}")
        parsed_param, end_offset = _parse_single_descriptor(param, offset=0, allow_void=False)
        if end_offset != len(param):
            raise ValueError(f"Invalid parameter descriptor {param!r}")
        valid_params.append(parsed_param)

    if not isinstance(return_descriptor, str):
        raise ValueError(
            f"Return descriptor must be a string, got {type(return_descriptor).__name__}"
        )

    parsed_ret, ret_end_offset = _parse_single_descriptor(
        return_descriptor, offset=0, allow_void=True
    )
    if ret_end_offset != len(return_descriptor):
        raise ValueError(f"Invalid return descriptor {return_descriptor!r}")

    return f"({''.join(valid_params)}){parsed_ret}"
