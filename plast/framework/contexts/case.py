# -*- coding: utf-8 -*-

from framework.api.checker import Checker as _checker

from framework.contexts import errors as _errors
from framework.contexts.logger import Logger as _log

import os
import shutil
import sys

class Case:
    def __init__(self, arguments):
        self.arguments = arguments
        self.name = os.path.basename(self.arguments.output)

        self.resources = {
            "case": self.arguments.output,
            "matches": os.path.join(self.arguments.output, "matches.{}".format(self.arguments.format.lower())),
            "evidences": [],
            "temporary": []
        }

        _log.debug("Initialized new case <{}> anchored to <{}>.".format(self.name, self.resources["case"]))

    def __del__(self):
        self._tear_down()

    def _tear_down(self):
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
        return "".join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(rounds))

    def _create_local_directory(self, directory, mask=0o700):
        try:
            os.makedirs(directory, mode=mask)
            _log.debug("Created local directory <{}>.".format(directory))

        except FileExistsError:
            _log.fault("Failed to create local directory due to existing object <{}>.".format(directory), trace=True)

        except (
            OSError,
            Exception):

            _log.fault("Failed to create local directory <{}>.".format(directory), trace=True)

    def require_temporary_directory(self, seed=None):
        seed = self._generate_nonce()

        while os.path.isdir(os.path.join(self.case.resources["case"], seed)):
            seed = self._generate_nonce()

        directory = os.path.join(self.case.resources["case"], seed)

        self._create_local_directory(directory)
        self.resources["temporary"].append(directory)

        return directory

    def create_arborescence(self):
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

    def parse_list(self, generator):
        for evidence in generator:
            self.resources["evidences"].append(evidence) if os.path.isfile(evidence) else _log.debug("Evidence <{}> not found.".format(evidence))

        _log.info("Currently tracking <{}> evidence(s).".format(len(self.resources["evidences"]))) if self.resources["evidences"] else _log.fault("No evidence(s) to process. Exiting.")
