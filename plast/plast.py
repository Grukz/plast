#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from framework.contexts.meta import Configuration as _conf
from framework.contexts.meta import Meta as _meta

_meta.set_package(__file__)
_conf._load_configuration(_meta.__conf__)

from framework.api.internal import magic as _magic
from framework.api.internal import parser as _parser
from framework.api.internal.checker import Checker as _checker
from framework.api.internal.loader import Loader as _loader

from framework.contexts import models as _models
from framework.contexts import case as _case
from framework.contexts.logger import Logger as _log

from framework.core import engine as _engine

import framework.modules.callback as _callback
import framework.modules.pre as _pre
import framework.modules.post as _post

import argparse
import multiprocessing

def _argparser(parser, modules={}):
    """
    .. py:function:: _argparser(parser, modules={})

    Command-line argument parsing function.

    :param parser: :code:`argparse.Parser` instance
    :type parser: class

    :param modules: dictionary containing loaded modules
    :type modules: dict

    :param parser: dictionary containing loaded module(s) and the processed command-line argument(s)
    :rtype: dict 
    """

    parser.add_argument(
        "-o", "--output", required=True, action=_parser.SingleAbsolutePath, metavar="PATH",
        help="path to the output directory to be created for the current case")

    parser.add_argument(
        "--callbacks", nargs="*", choices=_loader.render_modules(_callback, _models.Callback), default=_loader.render_modules(_callback, _models.Callback), action=_parser.Unique,
        help="select the callback(s) that will handle the resulting data [*]")

    parser.add_argument(
        "--fast", action="store_true",
        help="enable YARA's fast matching mode")

    parser.add_argument(
        "--format", choices=["json"], default=_conf.OUTPUT_FORMAT,
        help="output format for detection(s) {}".format(_conf.OUTPUT_FORMAT))

    parser.add_argument(
        "--hash-algorithms", nargs="+", action=_parser.Unique, metavar="NAME",
        choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s", "sha3_224", "sha3_256", "sha3_384", "sha3_512"], default=_conf.HASH_ALGORITHMS, 
        help="output format for detection(s), see hashlib API reference for supported algorithm(s) {}".format(_conf.HASH_ALGORITHMS))

    parser.add_argument(
        "--logging", choices=["debug", "info", "warning", "error", "critical", "suppress"], default=_conf.LOGGING_LEVEL,
        help="override the default console logging level [{}]".format(_conf.LOGGING_LEVEL))

    parser.add_argument(
        "--overwrite", action="store_true",
        help="force the overwriting of an existing output directory")

    parser.add_argument(
        "--post", nargs="*", choices=_loader.render_modules(_post, _models.Post), default=_loader.render_modules(_post, _models.Post), action=_parser.Unique,
        help="select the postprocessing module(s) that will handle the resulting data [*]")

    parser.add_argument(
        "--processes", type=int, choices=range(1, 1001), default=(multiprocessing.cpu_count() or _conf.FALLBACK_PROCESSES), metavar="NUMBER",
        help="override the number of concurrent processe(s) [{}]".format(multiprocessing.cpu_count() or _conf.FALLBACK_PROCESSES))

    for name, Module in _loader.iterate_modules(_pre, _models.Pre):
        subparser = parser.subparsers.add_parser(name, description=getattr(Module, "__description__", None), add_help=False)

        modules[name] = Module(subparser)
        modules[name].__name__ = name

        with _magic.Hole(argparse.ArgumentError):
            parser.register_help(subparser)

            if getattr(modules[name], "__version__", None):
                parser.register_version(subparser, modules[name].__name__, modules[name].__version__)

    return {
        "modules": modules,
        "arguments": parser.parse_args()
    }

def main(container):
    """
    .. py:function:: main(container)

    Main entry point for the program.

    :param self: dictionary containing loaded module(s) and processed command-line argument(s)
    :type self: dict
    """

    _log.set_console_level(container["arguments"].logging.upper())

    if not container["arguments"]._subparser:
        _log.fault("Nothing to be done.")

    if not _checker.number_rulesets():
        _log.fault("No YARA rulesets found. Nothing to be done.")

    case = _case.Case(container["arguments"])
    case.create_arborescence()

    Module = container["modules"][container["arguments"]._subparser]
    Module.case = case

    with _magic.Hole(Exception, action=lambda:_log.fault("Fatal exception raised within preprocessing module <{}>.".format(Module.__class__.__name__), trace=True)), _magic.Invocator(Module):
        Module.run()

    del Module

    if not (case.resources["evidences"]["files"] or case.resources["evidences"]["processes"]):
        _log.fault("No evidence(s) to process. Quitting.")

    _log.info("Currently tracking <{}> file(s) and <{}> live process(es).".format(len(case.resources["evidences"]["files"]), len(case.resources["evidences"]["processes"])))

    if case.arguments.fast:
        _log.warning("Fast mode is enabled. Some occurences may be ommited, be careful.")

    _engine.Engine(case).run()

if __name__ == "__main__":
    main(_argparser(_parser.CustomParser()))
