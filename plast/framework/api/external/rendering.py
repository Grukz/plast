# -*- coding: utf-8 -*-

from framework.api.internal.renderer import Renderer as _renderer

from framework.contexts import errors as _errors
from framework.contexts.logger import Logger as _log

__all__ = [
    "iterate_matches"
]

def iterate_matches(target):
    """
    .. py:function:: iterate_matches(target)

    Iterates over match(es) and yields a Python dictionary representation of each.

    :param target: path to the file containing JSON-encoded match(es)
    :type target: str
    
    :return: dictionary representation of the match
    :rtype: dict
    """

    with open(target) as matches:
        for match in matches:
            try:
                yield _renderer.from_json(match)

            except (
                _errors.CharacterEncodingError,
                _errors.InvalidObjectError):

                _log.error("Failed to interpret match <{}>.".format(match))
