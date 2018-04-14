# -*- coding: utf-8 -*-

from framework.contexts.meta import Meta as _meta

import argparse
import os.path

class CustomParser:
    """Custom CLI arguments parser."""

    def __init__(self):
        """
        Initialization method.

        Parameter(s)
        ------------
        self [namespace] current class instance
        """

        self.parser = argparse.ArgumentParser(
            prog=_meta.__package__,
            description="This tool must ALWAYS be used in a confined environment.",
            add_help=False)

        self.register_help(self.parser)
        self.register_version(self.parser, _meta.__package__, _meta.__version__)

        self._add_subparsers()

    def _add_subparsers(self, dest="_subparser"):
        """
        Instanciates an argparse.Parser.subparser object.

        Parameter(s)
        ------------
        self [namespace] current class instance
        dest [str] name of the argument representation of the selected subparser (defaults to "_subparser")
        """

        self.subparsers = self.parser.add_subparsers(dest=dest)

    def register_help(self, parser):
        """
        Adds a help menu in <parser>.

        Parameter(s)
        ------------
        self [namespace] current class instance
        parser [namespace] argparse.Parser or argparse.Parser.subparser instance
        """

        parser.add_argument(
            "--help", action="help",
            help="display the help menu")

    def register_version(self, parser, name, version):
        """
        Adds a version option in <parser>.

        Parameter(s)
        ------------
        self [namespace] current class instance
        parser [namespace] argparse.Parser or argparse.Parser.subparser instance
        name [str] name of the target
        version [str] version number of the target
        """

        parser.add_argument(
            "--version", action="version", version="{} {}".format(name, version),
            help="display the version number")

    def print_help(self):
        """
        Trigger the `print_help` method from the current parser.

        Parameter(s)
        ------------
        self [namespace] current class instance
        """

        self.parser.print_help()

    def add_argument(self, *args, **kwargs):
        """
        Registers a command-line argument in the main parser.

        Parameter(s)
        ------------
        self [namespace] current class instance
        *args [list] list of value(s)
        **kwargs [dict] dictionary containing key/value association(s)
        """

        self.parser.add_argument(*args, **kwargs)

    def parse_args(self):
        """
        Triggers the `parse_args` method from the main parser.

        Parameter(s)
        ------------
        self [namespace] current class instance

        Return value(s)
        ---------------
        [namespace] `argparse.Parser` instance containing the processed command-line arguments
        """

        return self.parser.parse_args()

class SingleAbsolutePath(argparse.Action):
    """Custom `argparse` action that calls the `os.path.abspath` method on the target."""

    def __call__(self, parser, namespace, values, option=None):
        """
        Callback method called when the action is invoked.

        Parameter(s)
        ------------
        self [namespace] current class instance
        parser [namespace] argparse.Parser or argparse.Parser.subparser instance
        namespace [namespace] object that will be returned by the `parse_args` method
        values [list] associated command-line arguments
        option [str] option string that was used to invoke this action (defaults to None)
        """

        setattr(namespace, self.dest, os.path.abspath(os.path.expanduser(values)))

class MultipleAbsolutePath(argparse._AppendAction):
    """Custom `argparse` action that calls the `os.path.abspath` method on every item."""

    def __call__(self, parser, namespace, values, option=None):
        """
        Callback method called when the action is invoked.

        Parameter(s)
        ------------
        self [namespace] current class instance
        parser [namespace] argparse.Parser or argparse.Parser.subparser instance
        namespace [namespace] object that will be returned by the `parse_args` method
        values [list] associated command-line arguments
        option [str] option string that was used to invoke this action (defaults to None)
        """

        setattr(namespace, self.dest, [os.path.abspath(os.path.expanduser(item)) for item in values])

class Unique(argparse.Action):
    """Custom `argparse` action that removes duplicate(s)."""

    def __call__(self, parser, namespace, values, option=None):
        """
        Callback method called when the action is invoked.

        Parameter(s)
        ------------
        self [namespace] current class instance
        parser [namespace] argparse.Parser or argparse.Parser.subparser instance
        namespace [namespace] object that will be returned by the `parse_args` method
        values [list] associated command-line arguments
        option [str] option string that was used to invoke this action (defaults to None)
        """

        setattr(namespace, self.dest, set(values))
