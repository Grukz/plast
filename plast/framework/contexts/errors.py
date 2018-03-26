# -*- coding: utf-8 -*-

class InvalidPackage(Exception):
    pass

class InvalidJSONObject(Exception):
    pass

class EncodingError(Exception):
    pass

class MalformatedData(Exception):
    pass

class ProcessorNotFound(Exception):
    pass

class ProcessorNotInherited(Exception):
    pass
