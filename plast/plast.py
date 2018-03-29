#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from framework.api import magic as _magic
from framework.api import parser as _parser
from framework.api.checker import Checker as _checker
from framework.api.loader import Loader as _loader

from framework.contexts import models as _models
from framework.contexts import case as _case
from framework.contexts.logger import Logger as _log

from framework.core import engine as _engine

import framework.processors.pre as _pre
import framework.processors.post as _post

import argparse
import multiprocessing

def argparser(parser, modules={}):
    parser.add_argument(
        "-o", "--output", required=True, action=_parser.SingleAbsolutePath, metavar="PATH",
        help="path to the output directory to be created for the current case")

    parser.add_argument(
        "--format", choices=["json"], default="json",
        help="output format for detection(s)")

    parser.add_argument(
        "--hash-algorithms", nargs="+", action=_parser.Unique, metavar="NAME",
        choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s", "sha3_224", "sha3_256", "sha3_384", "sha3_512"], default=["md5", "sha1", "sha256"], 
        help="output format for detection(s), see hashlib API reference for supported algorithm(s)")

    parser.add_argument(
        "--logging", choices=["debug", "info", "warning", "error", "critical", "suppress"], default="info",
        help="override the default console logging level")

    parser.add_argument(
        "--overwrite", action="store_true",
        help="force the overwriting of an existing output directory")

    parser.add_argument(
        "--post", nargs="+", choices=_loader.render_processors(_post, _models.Post), default=_loader.render_processors(_post, _models.Post), action=_parser.Unique,
        help="select the postprocessor(s) that will handle the resulting data")

    parser.add_argument(
        "--processes", type=int, choices=range(1, 100), default=(multiprocessing.cpu_count() or 4), metavar="NUMBER",
        help="override the number of concurrent processe(s)")

    for name, Processor in _loader.iterate_processors(_pre, _models.Pre):
        subparser = parser.subparsers.add_parser(name, description=Processor._description if hasattr(Processor, "_description") else None, add_help=False)

        modules[name] = Processor(subparser)
        modules[name].set_args()

        with _magic.Hole(argparse.ArgumentError):
            parser.set_help(subparser)

            if hasattr(modules[name], "_name") and hasattr(modules[name], "_version"):
                parser.set_version(subparser, modules[name]._name, modules[name]._version)

    return {
        "modules": modules,
        "arguments": parser.parse_args()
    }

def main(container):
    _log.set_console_level(container["arguments"].logging.upper())

    if not container["arguments"]._subparser:
        return

    if not _checker.number_rulesets():
        _log.fault("No YARA rulesets found. Nothing to be done.")

    case = _case.Case(container["arguments"])
    case.create_arborescence()

    Preprocessor = container["modules"][container["arguments"]._subparser]
    Preprocessor.init_case(case)

    with _magic.Hole(Exception, action=lambda:_log.fault("Fatal exception raised within preprocessor <{}>.".format(Preprocessor._name), trace=True)):
        _log.debug("Started preprocessing session <{}>.".format(Preprocessor._name))
        evidences = Preprocessor.run()
        _log.debug("Ended preprocessing session <{}>.".format(Preprocessor._name))

    if not evidences:
        _log.fault("No evidence(s) to process. Quitting.")

    case.parse_list(evidences)
    _engine.Engine(case).run()

if __name__ == "__main__":
    _log.debug("<TODO>Purge JSON rendering. Not that useful.</TODO>")
    _log.debug("<TODO>Use a Pandas DataFrame to contain detections and to pass them to Post modules.</TODO>")
    _log.debug("<TODO>Logging messages as decorators for  run() methods.</TODO>")
    _log.debug("<TODO>Replace set_args() method in Pre modules by __init__().</TODO>")
    _log.debug("<TODO>Callback class as a Post alternative to handle data on-the-fly.</TODO>")
    _log.debug("<TODO>Check for detections before launching Post modules.</TODO>")
    main(argparser(_parser.CustomParser()))
