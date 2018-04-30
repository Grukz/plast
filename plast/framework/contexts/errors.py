# -*- coding: utf-8 -*-

class InvalidPackageError(Exception):
    pass

class InvalidObjectError(Exception):
    pass

class CharacterEncodingError(Exception):
    pass

class MalformatedDataError(Exception):
    pass

class NotFoundError(Exception):
    pass

class ModuleInheritanceError(Exception):
    pass

class SystemNotSupportedError(Exception):
    pass

class InvalidMIMETypeError(Exception):
    pass
