from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class OuterMessage(_message.Message):
    __slots__ = ("field1", "field2", "field3", "field4", "field5")
    FIELD1_FIELD_NUMBER: _ClassVar[int]
    FIELD2_FIELD_NUMBER: _ClassVar[int]
    FIELD3_FIELD_NUMBER: _ClassVar[int]
    FIELD4_FIELD_NUMBER: _ClassVar[int]
    FIELD5_FIELD_NUMBER: _ClassVar[int]
    field1: int
    field2: InnerMessage
    field3: bytes
    field4: bytes
    field5: bytes
    def __init__(self, field1: _Optional[int] = ..., field2: _Optional[_Union[InnerMessage, _Mapping]] = ..., field3: _Optional[bytes] = ..., field4: _Optional[bytes] = ..., field5: _Optional[bytes] = ...) -> None: ...

class InnerMessage(_message.Message):
    __slots__ = ("field1", "field2")
    FIELD1_FIELD_NUMBER: _ClassVar[int]
    FIELD2_FIELD_NUMBER: _ClassVar[int]
    field1: int
    field2: bytes
    def __init__(self, field1: _Optional[int] = ..., field2: _Optional[bytes] = ...) -> None: ...
