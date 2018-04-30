# -*- coding: utf-8 -*-

from framework.contexts import models as _models

class Pre(_models.Pre):
    __author__ = "sk4la"
    __description__ = "Simple preprocessing module that feeds live process(es) to the engine."
    __license__ = "MIT <https://raw.githubusercontent.com/sk4la/plast/master/LICENSE>"
    __maintainer__ = ["sk4la"]
    __system__ = ["Darwin", "Linux", "Windows"]
    __version__ = "0.1"

    def __init__(self, parser):
        """
        .. py:function:: __init__(self, parser)

        Initialization method for the class.

        :param self: current class instance
        :type self: class

        :param parser: :code:`argparse.Parser.subparser` instance
        :type parser: list
        """

        parser.add_argument(
            "-a", "--attach", nargs="+", type=int, required=True, metavar="PID", 
            help="input process identifier(s)")

    def run(self):
        """
        .. py:function:: run(self)

        Main entry point for the module.

        :param self: current class instance
        :type self: class
        """

        for item in self.case.arguments.attach:
            self.case.track_process(item)
