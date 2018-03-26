# -*- coding: utf-8 -*-

from framework.api.checker import Checker as _checker
from framework.api.renderer import Renderer as _renderer

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
        self.__tear_down()

    def __tear_down(self):
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

    def __create_local_directory(self, directory, mask=0o700):
        try:
            os.makedirs(directory, mode=mask)
            _log.debug("Created local directory <{}>.".format(directory))

        except FileExistsError:
            _log.fault("Failed to create local directory due to existing object <{}>.".format(directory), trace=True)

        except (
            OSError,
            Exception):

            _log.fault("Failed to create local directory <{}>.".format(directory), trace=True)

    def __prompt(self, message, rounds=3, harsh_escape=True):
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

    def __generate_nonce(self, rounds=16):
        return "".join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(rounds))

    def require_temporary_directory(self, seed=None):
        seed = self.__generate_nonce()

        while os.path.isdir(os.path.join(self.case.resources["case"], seed)):
            seed = self.__generate_nonce()

        directory = os.path.join(self.case.resources["case"], seed)

        self.__create_local_directory(directory)
        self.resources["temporary"].append(directory)

        return directory

    def create_arborescence(self):
        if os.path.exists(self.resources["case"]):
            if not self.arguments.overwrite:
                self.__prompt("Overwrite existing object <{}> ? [y/N] ".format(self.resources["case"]))

            try:
                shutil.rmtree(self.resources["case"])
                _log.warning("Overwritten existing object <{}>.".format(self.resources["case"]))

            except (
                OSError,
                Exception):

                _log.fault("Failed to overwrite existing object <{}>.".format(self.resources["case"]), trace=True)

        self.__create_local_directory(self.resources["case"])

    def parse_list(self, data):
        try:
            data = _renderer.from_json(data)

        except _errors.InvalidJSONObject:
            _log.fault("Invalid JSON data from preprocessor.", trace=True)

        if not isinstance(data, list):
            _log.fault("Preprocessor must provide a list of evidence(s).", trace=True)

        for item in data:
            if os.path.isfile(item):
                self.resources["evidences"].append(item)

            else:
                _log.debug("Evidence <{}> not found.".format(item))

        _log.info("Currently tracking <{}> evidence(s).".format(len(self.resources["evidences"]))) if self.resources["evidences"] else _log.fault("No evidence(s) to process. Exiting.")
