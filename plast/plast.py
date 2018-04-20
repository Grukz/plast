#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from framework.contexts.meta import Configuration as _conf
from framework.contexts.meta import Meta as _meta

_meta.set_package(__file__)
_conf._load_configuration(_meta.__conf__)

from framework.api import magic as _magic
from framework.api import parser as _parser
from framework.api.checker import Checker as _checker
from framework.api.loader import Loader as _loader

from framework.contexts import models as _models
from framework.contexts import case as _case
from framework.contexts.logger import Logger as _log

from framework.core import engine as _engine

import framework.processors.callback as _callback
import framework.processors.pre as _pre
import framework.processors.post as _post

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
        "--callbacks", nargs="*", choices=_loader.render_processors(_callback, _models.Callback), default=_loader.render_processors(_callback, _models.Callback), action=_parser.Unique,
        help="select the callback(s) that will handle the resulting data [*]")

    parser.add_argument(
        "--format", choices=["json"], default="json",
        help="output format for detection(s) [json]")

    parser.add_argument(
        "--hash-algorithms", nargs="+", action=_parser.Unique, metavar="NAME",
        choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s", "sha3_224", "sha3_256", "sha3_384", "sha3_512"], default=_conf.HASH_ALGORITHMS, 
        help="output format for detection(s), see hashlib API reference for supported algorithm(s) [md5,sha1,sha256]")

    parser.add_argument(
        "--logging", choices=["debug", "info", "warning", "error", "critical", "suppress"], default="info",
        help="override the default console logging level [info]")

    parser.add_argument(
        "--overwrite", action="store_true",
        help="force the overwriting of an existing output directory")

    parser.add_argument(
        "--post", nargs="*", choices=_loader.render_processors(_post, _models.Post), default=_loader.render_processors(_post, _models.Post), action=_parser.Unique,
        help="select the postprocessor(s) that will handle the resulting data [*]")

    parser.add_argument(
        "--processes", type=int, choices=range(1, 100), default=(multiprocessing.cpu_count() or _conf.FALLBACK_PROCESSES), metavar="NUMBER",
        help="override the number of concurrent processe(s) [{}]".format(multiprocessing.cpu_count() or _conf.FALLBACK_PROCESSES))

    for name, Processor in _loader.iterate_processors(_pre, _models.Pre):
        subparser = parser.subparsers.add_parser(name, description=Processor.__description__ if hasattr(Processor, "__description__") else None, add_help=False)

        modules[name] = Processor(subparser)
        modules[name].__name__ = name

        with _magic.Hole(argparse.ArgumentError):
            parser.register_help(subparser)

            if hasattr(modules[name], "__version__"):
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

    Preprocessor = container["modules"][container["arguments"]._subparser]
    Preprocessor.case = case

    with _magic.Hole(Exception, action=lambda:_log.fault("Fatal exception raised within preprocessor <{}>.".format(Preprocessor.__class__.__name__), trace=True)), _magic.Invocator(Preprocessor):
        Preprocessor.run()

    del Preprocessor

    if not (case.resources["evidences"]["files"] or case.resources["evidences"]["processes"]):
        _log.fault("No evidence(s) to process. Quitting.")

    _log.info("Currently tracking <{}> file(s) and <{}> live process(es).".format(len(case.resources["evidences"]["files"]), len(case.resources["evidences"]["processes"])))

    _engine.Engine(case).run()

if __name__ == "__main__":
    main(_argparser(_parser.CustomParser()))
