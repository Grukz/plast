# -*- coding: utf-8 -*-

from framework.contexts.meta import Meta as _meta

import argparse
import os.path

class CustomParser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog=_meta.__package__,
            description="This tool must ALWAYS be used in a confined environment.",
            add_help=False)

        self.register_help(self.parser)
        self.register_version(self.parser, _meta.__package__, _meta.__version__)

        self._add_subparsers()

    def _add_subparsers(self, dest="_subparser"):
        self.subparsers = self.parser.add_subparsers(dest=dest)

    def register_help(self, parser):
        parser.add_argument(
            "--help", action="help",
            help="display the help menu")

    def register_version(self, parser, name, version):
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
