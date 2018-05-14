# -*- coding: utf-8 -*-

__all__ = [
    "CharacterEncodingError",
    "InvalidMIMETypeError",
    "InvalidObjectError",
    "InvalidPackageError",
    "MalformatedDataError",
    "ModuleInheritanceError",
    "NotFoundError",
    "SystemNotSupportedError",
]

class CharacterEncodingError(Exception):
    pass

class InvalidMIMETypeError(Exception):
    pass

class InvalidObjectError(Exception):
    pass

class InvalidPackageError(Exception):
    pass

class MalformatedDataError(Exception):
    pass

class ModuleInheritanceError(Exception):
    pass

class NotFoundError(Exception):
    pass

class SystemNotSupportedError(Exception):
    pass
