# -*- coding: utf-8 -*-

from framework.contexts import errors as _errors

try:
    import simplejson as json

except (
    ImportError,
    Exception):

    _log.fault("Import error.", trace=True)

__all__ = [
    "Renderer"
]

class Renderer:
    """Helper class for specific formatting and rendering."""

    @staticmethod
    def from_json(data):
        """
        .. py:function:: from_json(data)

        Renders JSON-encoded data as a Python dictionary.

        :param data: JSON-encoded data to render
        :type data: str

        :return: dictionary translation of :code:`data`
        :rtype: dict

        :raises CharacterEncodingError: if :code:`data` cannot be decoded
        :raises InvalidObjectError: if :code:`data` is malformated
        """

        try:
            return json.loads(data)

        except UnicodeDecodeError:
            raise _errors.CharacterEncodingError

        except (
            OverflowError,
            TypeError,
            ValueError,
            Exception):

            raise _errors.InvalidObjectError

    @staticmethod
    def to_json(data):
        """
        .. py:function:: to_json(data)

        Renders a Python dictionary as JSON-encoded data.

        :param data: data to render
        :type data: dict

        :return: JSON-encoded translation of :code:`data`
        :rtype: str

        :raises CharacterEncodingError: if :code:`data` cannot be encoded
        :raises InvalidObjectError: if :code:`data` is malformated
        """

        try:
            return json.dumps(data)

        except UnicodeDecodeError:
            raise _errors.CharacterEncodingError

        except (
            OverflowError,
            TypeError,
            ValueError,
            Exception):

            raise _errors.InvalidObjectError
