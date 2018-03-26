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
        "--format", choices=["JSON"], default="JSON",
        help="output format for detection(s)")

    parser.add_argument(
        "--logging", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "SUPPRESS"], default="INFO",
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
    _log.set_console_level(container["arguments"].logging)

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
    main(argparser(_parser.CustomParser()))
