# -*- coding: utf-8 -*-

from framework.contexts import errors as _errors
from framework.contexts.logger import Logger as _log

import glob
import itertools
import magic
import os.path
import types

def iterate_files(files):
    """
    .. py:function:: iterate_files(files)

    Iterates over file(s) and yields the corresponding path if existing.

    :param files: list of file(s) path(s)
    :type files: list
    
    :return: path to the existing file(s)
    :rtype: str
    """

    for item in files:
        if not os.path.isfile(item):
            _log.error("File not found <{}>.".format(item))
            continue

        yield item

def enumerate_matching_files(reference, patterns, recursive=False):
    """
    .. py:function:: enumerate_matching_files(reference, patterns)

    Returns an iterator pointing to the matching file(s) based on shell-like pattern(s).

    :param reference: absolute path to the rulesets directory
    :type reference: str

    :param patterns: list of globbing filter(s) to apply for the search
    :type patterns: list

    :param recursive: set to True to walk directory(ies) recursively
    :type recursive: bool

    :return: set containing the absolute path(s) of the matching file(s)
    :rtype: set
    """

    return set(itertools.chain.from_iterable(glob.iglob(os.path.join(reference, ("**" if recursive else ""), pattern), recursive=recursive) for pattern in patterns))

def check_mime_type(target, types=[]):
    """
    .. py:function:: check_mime_type(target, types=[])

    Checks wether the MIME-type of :code:`target` is included in :code:`types`.

    :param target: absolute path to the file to check
    :type target: str

    :param types: list of authorized MIME-types
    :type types: list

    :raises InvalidMIMETypeError: if the MIME-type of :code:`target` is not present in :code:`types`
    """

    if not magic.from_file(target, mime=True) in types:
        raise _errors.InvalidMIMETypeError
