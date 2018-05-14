# -*- coding: utf-8 -*-

from framework.api.internal import parser as _parser

from framework.contexts import models as _models
from framework.contexts.logger import Logger as _log

import os.path

# try:
#     import patoolib

# except (
#     ImportError,
#     Exception):

#     _log.fault("Import error.", trace=True)

__all__ = [
    "Pre"
]

class Pre(_models.Pre):
    __author__ = "sk4la"
    __description__ = "Simple preprocessing module that unpacks archive(s) and feeds resulting evidence(s) to the engine."
    __license__ = "MIT <https://github.com/sk4la/plast/blob/master/LICENSE.adoc>"
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
            "-i", "--input", nargs="+", action=_parser.AbsolutePathMultiple, required=True, metavar="PATH", 
            help="input archive(s)")

    def _unpack_file(self, file):
        # patoolib.extract_archive("archive.zip", outdir="/tmp")
        # patoolib.test_archive("dist.tar.gz", verbosity=1)
        # patoolib.list_archive("package.deb")
        # patoolib.create_archive("/path/to/myfiles.zip", ("file1.txt", "dir/"))
        # patoolib.diff_archives("release1.0.tar.gz", "release2.0.zip")
        # patoolib.search_archive("def urlopen", "python3.3.tar.gz")
        # patoolib.repack_archive("linux-2.6.33.tar.gz", "linux-2.6.33.tar.bz2")
        pass

    def run(self):
        """
        .. py:function:: run(self)

        Main entry point for the module.

        :param self: current class instance
        :type self: class
        """

        tmp = self.case.require_temporary_directory()

        for item in self.case.arguments.input:
            if os.path.isfile(item):
                _log.debug("Tracking file <{}> to <{}>.".format(file, tmp))

            elif os.path.isdir(item):
                _log.warning("Directory <{}> is not an archive. Ignoring.".format(item))

            else:
                _log.warning("Unknown inode type for object <{}>.".format(item))
