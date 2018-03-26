# -*- coding: utf-8 -*-

from framework.contexts.meta import Meta as _meta

import functools
import logging
import logging.config
import multiprocessing
import sys

class Logger:
    _lock = multiprocessing.Lock()

    def __synchronize(destination):
        @functools.wraps(destination)
        def synchronize(*args, **kwargs):
            Logger._lock.acquire()
            destination(*args, **kwargs)
            Logger._lock.release()

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
                "filename": "/var/log/{0}/{0}.log".format(_meta._name)
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
    def __set_console_state(state):
        Logger.console.disabled = not state

    @staticmethod
    def set_console_level(level):
        Logger.__set_console_state(False) if level == "SUPPRESS" else Logger.console.setLevel(getattr(logging, level))

    @staticmethod
    @__synchronize
    def debug(message):
        Logger.core.debug(message)
        Logger.console.debug(message)

    @staticmethod
    @__synchronize
    def info(message):
        Logger.core.info(message)
        Logger.console.info(message)

    @staticmethod
    @__synchronize
    def warning(message):
        Logger.core.warning(message)
        Logger.console.warning(message)

    @staticmethod
    @__synchronize
    def error(message):
        Logger.core.error(message)
        Logger.console.error(message)

    @staticmethod
    @__synchronize
    def critical(message):
        Logger.core.critical(message)
        Logger.console.critical(message)

    @staticmethod
    @__synchronize
    def exception(message):
        Logger.core.exception(message)
        Logger.console.exception(message)

    @staticmethod
    def fault(message, trace=False):
        Logger.__set_console_state(True)
        Logger.critical(message) if not trace else Logger.exception(message)
        sys.exit(1)
