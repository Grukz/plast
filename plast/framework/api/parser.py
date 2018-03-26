# -*- coding: utf-8 -*-

from framework.contexts.logger import Logger as _log
from framework.contexts.meta import Meta as _meta

import argparse
import copy
import os.path

class CustomParser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog=_meta._name,
            description="This tool must ALWAYS be used in a confined environment.",
            add_help=False)

        self.set_help(self.parser)
        self.set_version(self.parser, _meta._name, _meta._version)

        self.__add_subparsers()

    def __add_subparsers(self, dest="_subparser"):
        self.subparsers = self.parser.add_subparsers(dest=dest)

    def set_help(self, parser):
        parser.add_argument(
            "--help", action="help",
            help="display the help menu")

    def set_version(self, parser, name, version):
        parser.add_argument(
            "--version", action="version", version="{} {}".format(name, version),
            help="display the version number")

    def print_help(self):
        self.parser.print_help()

    def add_argument(self, *args, **kwargs):
        self.parser.add_argument(*args, **kwargs)

    def parse_args(self):
        return self.parser.parse_args()

class SingleAbsolutePath(argparse.Action):
    def __call__(self, parser, namespace, values, option=None):
        setattr(namespace, self.dest, os.path.abspath(os.path.expanduser(values)))

class MultipleAbsolutePath(argparse._AppendAction):
    def __call__(self, parser, namespace, values, option=None):
        setattr(namespace, self.dest, [os.path.abspath(os.path.expanduser(item)) for item in values])

class Unique(argparse.Action):
    def __call__(self, parser, namespace, values, option=None):
        setattr(namespace, self.dest, set(values))
