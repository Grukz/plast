# -*- coding: utf-8 -*-

from framework.api.checker import Checker as _checker

from framework.contexts import errors as _errors
from framework.contexts.logger import Logger as _log

import os
import psutil
import shutil
import sys

class Case:
    """Centralizes the current case's data."""

    def __init__(self, arguments):
        """
        .. py:function:: __init__(self, arguments)

        Initialization method for the class.

        :param self: current class instance
        :type self: class

        :param arguments: :code:`argparse.Parser` instance containing the processed command-line arguments
        :type arguments: list
        """

        self.arguments = arguments
        self.name = os.path.basename(self.arguments.output)

        self.resources = {
            "case": self.arguments.output,
            "matches": os.path.join(self.arguments.output, "matches.{}".format(self.arguments.format.lower())),
            "evidences": {
                "files": [],
                "processes": []
            },
            "temporary": []
        }

        _log.debug("Initialized new case <{}> anchored to <{}>.".format(self.name, self.resources["case"]))

    def __del__(self):
        """
        .. py:function:: __del__(self)

        Destruction method that calls the teardown function(s).

        :param self: current class instance
        :type self: class
        """

        self._tear_down()

    def _tear_down(self):
        """
        .. py:function:: _tear_down(self)

        Cleanup method called on class destruction that gets rid of the temporary artifact(s).

        :param self: current class instance
        :type self: class
        """

        for artifact in self.resources["temporary"]:
            try:
                shutil.rmtree(artifact)
                _log.debug("Removed temporary artifact <{}>.".format(artifact))

            except FileNotFoundError:
                _log.debug("Temporary artifact not found <{}>.".format(artifact))

            except (
                OSError,
                Exception):

                _log.exception("Failed to remove temporary artifact <{}>.".format(artifact))

    def _prompt(self, message, rounds=3, harsh_escape=True):
        """
        .. py:function:: _prompt(self, message, rounds=3, harsh_escape=True)

        Prompts the user with a yes/no question and wait for a valid answer.

        :param self: current class instance
        :type self: class

        :param message: question to print
        :type message: str

        :param rounds: number of times to repeat the question
        :type rounds: int

        :param harsh_escape: exit the program if :code:`rounds` has been reached
        :type harsh_escape: bool
        """

        for _ in range(rounds):
            try:
                answer = _checker.sanitize_data(input(message))

            except _errors.MalformatedData:
                _log.fault("Malformated input.")

            except KeyboardInterrupt:
                sys.stderr.write("\n")
                _log.fault("SIGINT trapped.")

            if not answer or answer in "nN":
                _log.fault("Aborted due to manual user interruption.")

            elif answer in "yY":
                return

        if harsh_escape:
            _log.fault("No valid answer provided.")

    def _generate_nonce(self, rounds=16):
        """
        .. py:function:: _generate_nonce(self, rounds=16)

        Generates a random string.

        :param self: current class instance
        :type self: class

        :param rounds: number of characters to generate
        :type rounds: int

        :return: random string of :code:`rounds` character(s)
        :rtype: str
        """

        return "".join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(rounds))

    def _create_local_directory(self, directory, mask=0o700):
        """
        .. py:function:: _create_local_directory(self, directory, mask=0o700)

        Creates a directory on the filesystem.

        :param self: current class instance
        :type self: class

        :param directory: absolute path to the directory to create
        :type directory: str

        :param mask: permissions bit mask to apply for the newly created :code:`directory` and its parents if necessary
        :type mask: oct

        :return: random string of :code:`rounds` characters
        :rtype: str
        """

        try:
            os.makedirs(directory, mode=mask)
            _log.debug("Created local directory <{}>.".format(directory))

        except FileExistsError:
            _log.fault("Failed to create local directory due to existing object <{}>.".format(directory), trace=True)

        except (
            OSError,
            Exception):

            _log.fault("Failed to create local directory <{}>.".format(directory), trace=True)

    def create_arborescence(self):
        """
        .. py:function:: create_arborescence(self)

        Creates the base arborescence for the current case.

        :param self: current class instance
        :type self: class
        """

        if os.path.exists(self.resources["case"]):
            if not self.arguments.overwrite:
                self._prompt("Overwrite existing object <{}> ? [y/N] ".format(self.resources["case"]))

            try:
                shutil.rmtree(self.resources["case"])
                _log.warning("Overwritten existing object <{}>.".format(self.resources["case"]))

            except (
                OSError,
                Exception):

                _log.fault("Failed to overwrite existing object <{}>.".format(self.resources["case"]), trace=True)

        self._create_local_directory(self.resources["case"])

    def require_temporary_directory(self, seed=None):
        """
        .. py:function:: require_temporary_directory(self, seed=None)

        Creates a temporary directory in the case directory that will be deleted after processing is over.

        :param self: current class instance
        :type self: class

        :param seed: random string
        :type seed: str

        :return: absolute path to the newly created temporary directory
        :rtype: str
        """

        seed = self._generate_nonce()

        while os.path.isdir(os.path.join(self.case.resources["case"], seed)):
            seed = self._generate_nonce()

        directory = os.path.join(self.case.resources["case"], seed)

        self._create_local_directory(directory)
        self.resources["temporary"].append(directory)

        return directory

    def track_file(self, evidence):
        """
        .. py:function:: track_file(self, evidence)

        Checks and registers an evidence file for processing.

        :param self: current class instance
        :type self: class

        :param evidence: absolute path to the evidence file
        :type evidence: str
        """

        if os.path.isfile(evidence):
            self.resources["evidences"]["files"].append(evidence)
            _log.debug("Tracking file <{}>.".format(evidence))

        else:
            _log.warning("Evidence <{}> not found or invalid.".format(evidence))

    def track_files(self, evidences):
        """
        .. py:function:: track_files(self, evidences)

        Checks and registers multiple evidence files for processing.

        :param self: current class instance
        :type self: class

        :param evidence: list of absolute path(s) to the evidence file(s)
        :type evidence: list
        """

        for evidence in _magic._iterate_files(evidences):
            self.track_file(evidence)

    def track_process(self, pid, reference=[process.info for process in psutil.process_iter(attrs=["pid"])]):
        """
        .. py:function:: track_process(self, pid, reference=[process.info for process in psutil.process_iter(attrs=["name", "pid"])])

        Checks wether a process exists on the local machine and registers it for processing.

        :param self: current class instance
        :type self: class

        :param pid: process identifier
        :type pid: int

        :param reference: list of dictionaries containing processes key/value associations
        :type reference: list
        """

        if not isinstance(pid, int):
            _log.error("Invalid PID format <{}>.".format(pid))
            return

        for process in reference:
            if int(process["pid"]) == pid:
                self.resources["evidences"]["processes"].append(pid)
                _log.debug("Tracking live process matching PID <{}>.".format(pid))
                return

        _log.warning("Process <{}> not found.".format(pid))

    def track_processes(self, processes):
        """
        .. py:function:: track_processes(self, processes)

        Parses process identifier(s) and registers every existing process for further processing.

        :param self: current class instance
        :type self: class

        :param processes: list of process identifier(s)
        :type processes: list
        """

        for pid in processes:
            self.track_process(pid)
