# -*- coding: utf-8 -*-

from framework.contexts.meta import Meta as _meta

import functools
import logging
import logging.config
import multiprocessing
import sys

class Logger:
    """Main logger class."""

    _lock = multiprocessing.Lock()

    def _synchronize(destination):
        """
        .. py:function:: _synchronize(destination)

        Synchronizes the file writing operations through multiprocessing.Lock.

        :param destination: function to wrap
        :type destination: class

        :return: wrapper function
        :rtype: class
        """

        @functools.wraps(destination)
        def synchronize(*args, **kwargs):
            with Logger._lock:
                destination(*args, **kwargs)

        return synchronize

    logging.config.dictConfig({
        "version": 1,
        "disable_existing_loggers": True,
        "formatters": {
            "standard": {
                "format": "%(asctime)s %(levelname)-8s %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S"
            },
            "colored": {
                "()": "colorlog.ColoredFormatter",
                "format": "%(asctime)s %(log_color)s%(levelname)-8s%(reset)s %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
                "reset": True,
                "log_colors": {
                    "DEBUG": "white",
                    "INFO": "green",
                    "WARNING":"yellow",
                    "ERROR": "red",
                    "CRITICAL": "red"
                }
            }
        },
        "handlers": {
            "core": {
                "class": "logging.handlers.RotatingFileHandler",
                "formatter": "standard",
                "level": "DEBUG",
                "mode": "a",
                "maxBytes": 1024 * 1024 * 10,
                "backupCount": 10,
                "filename": "/var/log/{0}/{0}.log".format(_meta.__package__)
            },
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "colored",
                "level": "DEBUG"
            }
        },
        "loggers": {
            "core" : {
                "level": "DEBUG",
                "handlers": [
                    "core"
                ]
            },
            "console" : {
                "level": "DEBUG",
                "handlers": [
                    "console"
                ]
            }
        }
    })

    core = logging.getLogger("core")
    console = logging.getLogger("console")

    @staticmethod
    def _set_console_state(state):
        """
        .. py:function:: _set_console_state(state)

        Enables or disables the console stream.

        :param state: boolean representing the future state of the console stream
        :type state: bool
        """

        Logger.console.disabled = not state

    @staticmethod
    def set_console_level(level):
        """
        .. py:function:: set_console_level(level)

        Sets the console logging level.

        :param level: name of the level to set the logging policy to
        :type level: str
        """

        Logger._set_console_state(False) if level == "SUPPRESS" else Logger.console.setLevel(getattr(logging, level))

    @staticmethod
    @_synchronize
    def debug(message):
        """
        .. py:function:: debug(message)

        Prints a debug message.

        :param message: data to print
        :type message: str
        """

        Logger.core.debug(message)
        Logger.console.debug(message)

    @staticmethod
    @_synchronize
    def info(message):
        """
        .. py:function:: info(message)

        Prints an information message.

        :param message: data to print
        :type message: str
        """

        Logger.core.info(message)
        Logger.console.info(message)

    @staticmethod
    @_synchronize
    def warning(message):
        """
        .. py:function:: warning(message)

        Prints a warning message.

        :param message: data to print
        :type message: str
        """

        Logger.core.warning(message)
        Logger.console.warning(message)

    @staticmethod
    @_synchronize
    def error(message):
        """
        .. py:function:: error(message)

        Prints an error message.

        :param message: data to print
        :type message: str
        """

        Logger.core.error(message)
        Logger.console.error(message)

    @staticmethod
    @_synchronize
    def critical(message):
        """
        .. py:function:: critical(message)

        Prints a critical error message.

        :param message: data to print
        :type message: str
        """

        Logger.core.critical(message)
        Logger.console.critical(message)

    @staticmethod
    @_synchronize
    def exception(message):
        """
        .. py:function:: exception(message)

        Prints the last exception traceback along with an error message.

        :param message: data to print
        :type message: str
        """

        Logger.core.exception(message)
        Logger.console.exception(message)

    @staticmethod
    def fault(message, trace=False):
        """
        .. py:function:: fault(message, trace=False)

        Prints the last exception traceback along with an error message then exits the program.

        :param message: data to print
        :type message: str

        :param trace: enable traceback of the last exception raised
        :type trace: bool
        """

        Logger._set_console_state(True)
        Logger.critical(message) if not trace else Logger.exception(message)
        sys.exit(1)
