# -*- coding: utf-8 -*-

from framework.contexts import errors as _errors

try:
    import simplejson as json

except (
    ImportError,
    Exception):

    _log.fault("Import error.", trace=True)

class Renderer:
    """Helper class for specific formatting and rendering."""

    @staticmethod
    def from_json(data):
        """
        Renders JSON-encoded data as a Python dictionary.

        Parameter(s)
        ------------
        data [str] JSON-encoded data to render

        Return value(s)
        ---------------
        [dict] dictionary translation of <data>
        """

        try:
            return json.loads(data)

        except UnicodeDecodeError:
            raise _errors.EncodingError

        except (
            OverflowError,
            TypeError,
            ValueError,
            Exception):

            raise _errors.InvalidObject

    @staticmethod
    def to_json(data):
        """
        Renders a Python dictionary as JSON-encoded data.

        Parameter(s)
        ------------
        data [dict] data to render

        Return value(s)
        ---------------
        [dict] JSON-encoded translation of <data>
        """

        try:
            return json.dumps(data)

        except UnicodeDecodeError:
            raise _errors.EncodingError

        except (
            OverflowError,
            TypeError,
            ValueError,
            Exception):

            raise _errors.InvalidObject
