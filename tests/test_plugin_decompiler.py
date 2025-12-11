"""Test the decompiler section of the plugin."""

import datetime

from azul_runner import (
    FV,
    Event,
    EventData,
    EventParent,
    Filepath,
    JobResult,
    State,
    test_template,
)

from azul_plugin_python.main import AzulPluginPython


class TestExecute(test_template.TestPlugin):
    """Test decompiling various pyc files.

    - test on .pyc with path
    - test on .pyc with timestamp
    - test on .pyc that partially decompiles (now fixed)
    - test on fake .pyc (bytecode header + random data)
    - test on random data
    """

    PLUGIN_TO_TEST = AzulPluginPython
    MULTI_PLUGIN_KEY = "decompiler"
    MULTI_PLUGIN_KEY_SECONDARY = "pylingual"
    FILE_FORMAT_OVERRIDE = "code/python"

    def test_random_data(self):
        """Random input data, plugin will opt out after finding no python bytecode header."""
        result = self.do_execution(
            entity_attrs={"file_format": self.FILE_FORMAT_OVERRIDE},
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "8678b5c2f62856b58566d966d987941a2b88802f556ae671a0e7d15c161f5224",
                        "Random input data, plugin will opt out after finding no python bytecode header.",
                    ),
                )
            ],
            verify_input_content=False,
        )
        self.assertJobResult(
            result.get(self.MULTI_PLUGIN_KEY),
            JobResult(
                state=State(
                    State.Label.OPT_OUT,
                    failure_name="unknown_python_magic_bytes",
                    message="python magic bytes unknown or not a pyc file",
                )
            ),
        )

        self.assertJobResult(
            result.get(self.MULTI_PLUGIN_KEY_SECONDARY),
            JobResult(
                state=State(
                    State.Label.OPT_OUT,
                    failure_name="not_pylingual_compatible",
                    message="file cannot be decompiled by pylingual, either the python version is too old or it's not bytecode",
                )
            ),
        )

    def test_fake_pyc(self):
        """Random input data prepended with a valid Python bytecode header."""
        result = self.do_execution(
            entity_attrs={"file_format": self.FILE_FORMAT_OVERRIDE},
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "50fbed94968973fae97227ad08569d52a18ce401111c24bd036659129a031126",
                        "Random input data prepended with a valid Python bytecode header.",
                    ),
                )
            ],
        )
        self.assertJobResult(
            result.get(self.MULTI_PLUGIN_KEY),
            JobResult(state=State(State.Label.ERROR_EXCEPTION, message="decompilation failed")),
        )

        self.assertJobResult(
            result.get(self.MULTI_PLUGIN_KEY_SECONDARY),
            JobResult(
                state=State(
                    State.Label.OPT_OUT,
                    failure_name="not_pylingual_compatible",
                    message=result.get(self.MULTI_PLUGIN_KEY_SECONDARY).state.message,
                )
            ),
        )

    def test_timestamp(self):
        """Python bytecode with a header containing a timestamp.

        .pyc file extracted from 90e0eef8bbf5166156461512bc0252fa, available from VirusTotal.
        """
        result = self.do_execution(
            entity_attrs={"file_format": self.FILE_FORMAT_OVERRIDE},
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "96a0fc1b700c072571ec253d854c0bd44ff434749ec58637587297f02240ab76",
                        "Python bytecode with a header containing a timestamp.",
                    ),
                )
            ],
        )
        # hashes are prone to change
        main_result = result.get(self.MULTI_PLUGIN_KEY)
        main_result.data = {}
        main_result.events[0].data[0].hash = "grape"
        main_result.events[1].sha256 = "grape"
        main_result.events[1].data[0].hash = "grape"
        self.assertJobResult(
            main_result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="96a0fc1b700c072571ec253d854c0bd44ff434749ec58637587297f02240ab76",
                        data=[
                            EventData(
                                hash="grape",
                                label="text",
                                language="python",
                            )
                        ],
                        features={
                            "python_compile_time": [FV(datetime.datetime(2013, 8, 4, 2, 54, 50))],
                            "python_version": [FV("Python 3.4")],
                            "tag": [FV("python_bytecode")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="96a0fc1b700c072571ec253d854c0bd44ff434749ec58637587297f02240ab76",
                        ),
                        entity_type="binary",
                        entity_id="grape",
                        relationship={"action": "decompiled"},
                        data=[EventData(hash="grape", label="content")],
                        features={
                            "filename": [FV(Filepath("ataque4.py"))],
                            "tag": [FV("decompiled_script"), FV("python_script")],
                        },
                    ),
                ],
            ),
        )

        self.assertJobResult(
            result.get(self.MULTI_PLUGIN_KEY_SECONDARY),
            JobResult(
                state=State(
                    State.Label.OPT_OUT,
                    failure_name="not_pylingual_compatible",
                    message=result.get(self.MULTI_PLUGIN_KEY_SECONDARY).state.message,
                )
            ),
        )

    def test_filepath(self):
        """Python bytecode that unpacks to a long file path.

        .pyc file extracted from 932a7f813e12a3be34bf5faf7ae654ab, available from VirusTotal.
        """
        result = self.do_execution(
            entity_attrs={"file_format": self.FILE_FORMAT_OVERRIDE},
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "57dd046e868c7c2be46d15cc3377dbb12018d666640cc14ae3a48f49c73acaf1",
                        "Python bytecode that unpacks to a long file path.",
                    ),
                )
            ],
        )
        # hashes are prone to change
        main_result = result.get(self.MULTI_PLUGIN_KEY)
        main_result.data = {}
        main_result.events[0].data[0].hash = "grape"
        main_result.events[1].sha256 = "grape"
        main_result.events[1].data[0].hash = "grape"
        self.assertJobResult(
            main_result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="57dd046e868c7c2be46d15cc3377dbb12018d666640cc14ae3a48f49c73acaf1",
                        data=[
                            EventData(
                                hash="grape",
                                label="text",
                                language="python",
                            )
                        ],
                        features={"python_version": [FV("Python 3.6")], "tag": [FV("python_bytecode")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="57dd046e868c7c2be46d15cc3377dbb12018d666640cc14ae3a48f49c73acaf1",
                        ),
                        entity_type="binary",
                        entity_id="grape",
                        relationship={"action": "decompiled"},
                        data=[
                            EventData(
                                hash="grape",
                                label="content",
                            )
                        ],
                        features={
                            "filename": [
                                FV(Filepath("D:\\PROYECTOS • KTZ\\Codigos\\Spotify Key Generator\\adbuz.py"))
                            ],
                            "tag": [FV("decompiled_script"), FV("python_script")],
                        },
                    ),
                ],
                data={},
            ),
        )

        self.assertJobResult(
            result.get(self.MULTI_PLUGIN_KEY_SECONDARY),
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="57dd046e868c7c2be46d15cc3377dbb12018d666640cc14ae3a48f49c73acaf1",
                        data=[
                            EventData(
                                hash="c1abf4590dcf2875e1099b4a4b0f34e0ab2c72d5c1850109a6e8dd21efb1d417", label="text"
                            )
                        ],
                    )
                ],
                data={"c1abf4590dcf2875e1099b4a4b0f34e0ab2c72d5c1850109a6e8dd21efb1d417": b""},
            ),
        )

    def test_partial_no_more(self):
        """Python bytecode that partially decompiles with uncompyle6 3.6.7.

        As of uncompyle6 3.7.3 this appears now fixed.
        .pyc file extracted from 6dafe057468d697621db5c736a001951, available from VirusTotal.
        """
        result = self.do_execution(
            entity_attrs={"file_format": self.FILE_FORMAT_OVERRIDE},
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "f9889a39046086f5e6297b01c58d92ce550c1fcbab5fe1d966c273bd2b1fb554",
                        "Python bytecode that partially decompiles with uncompyle6 3.6.7.",
                    ),
                )
            ],
        )
        # hashes are prone to change
        # hashes are prone to change
        main_result = result.get(self.MULTI_PLUGIN_KEY)
        main_result.data = {}
        main_result.events[0].data[0].hash = "grape"
        main_result.events[1].sha256 = "grape"
        main_result.events[1].data[0].hash = "grape"
        self.assertJobResult(
            main_result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="f9889a39046086f5e6297b01c58d92ce550c1fcbab5fe1d966c273bd2b1fb554",
                        data=[
                            EventData(
                                hash="grape",
                                label="text",
                                language="python",
                            )
                        ],
                        features={"python_version": [FV("Python 3.8")], "tag": [FV("python_bytecode")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="f9889a39046086f5e6297b01c58d92ce550c1fcbab5fe1d966c273bd2b1fb554",
                        ),
                        entity_type="binary",
                        entity_id="grape",
                        relationship={"action": "decompiled"},
                        data=[
                            EventData(
                                hash="grape",
                                label="content",
                            )
                        ],
                        features={
                            "filename": [FV("nanobomber.py")],
                            "tag": [FV("decompiled_script"), FV("python_script")],
                        },
                    ),
                ],
            ),
        )

        self.assertJobResult(
            result.get(self.MULTI_PLUGIN_KEY_SECONDARY),
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="f9889a39046086f5e6297b01c58d92ce550c1fcbab5fe1d966c273bd2b1fb554",
                        data=[
                            EventData(
                                hash="6f8367aafc86af6b2a6adcbf0e2adec67cc5fc76c3bbb7117c1acf3ca0f5db36",
                                label="text",
                            )
                        ],
                    )
                ],
                data={"6f8367aafc86af6b2a6adcbf0e2adec67cc5fc76c3bbb7117c1acf3ca0f5db36": b""},
            ),
        )

    def test_python27(self):
        """Test something from Python 2.7.

        .pyc file extracted from 5b678e095411d34d8676ced1f2c72e98, available from VirusTotal.
        """
        result = self.do_execution(
            entity_attrs={"file_format": self.FILE_FORMAT_OVERRIDE},
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "15725467b1e6c1bfbff1cdef632a603e4efe85d1321bf629d0a4692e03c8d704",
                        "Malicious python pyc file as part of a backdoor.",
                    ),
                )
            ],
        )
        # hashes are prone to change
        main_result = result.get(self.MULTI_PLUGIN_KEY)
        main_result.data = {}
        main_result.events[0].data[0].hash = "grape"
        main_result.events[1].sha256 = "grape"
        main_result.events[1].data[0].hash = "grape"
        self.assertJobResult(
            main_result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="15725467b1e6c1bfbff1cdef632a603e4efe85d1321bf629d0a4692e03c8d704",
                        data=[
                            EventData(
                                hash="grape",
                                label="text",
                                language="python",
                            )
                        ],
                        features={"python_version": [FV("Python 2.7")], "tag": [FV("python_bytecode")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="15725467b1e6c1bfbff1cdef632a603e4efe85d1321bf629d0a4692e03c8d704",
                        ),
                        entity_type="binary",
                        entity_id="grape",
                        relationship={"action": "decompiled"},
                        data=[
                            EventData(
                                hash="grape",
                                label="content",
                            )
                        ],
                        features={
                            "filename": [FV(Filepath("reverse_backdoor.py"))],
                            "tag": [FV("decompiled_script"), FV("python_script")],
                        },
                    ),
                ],
                data={},
            ),
        )

        self.assertJobResult(
            result.get(self.MULTI_PLUGIN_KEY_SECONDARY),
            JobResult(
                state=State(
                    State.Label.OPT_OUT,
                    failure_name="not_pylingual_compatible",
                    message=result.get(self.MULTI_PLUGIN_KEY_SECONDARY).state.message,
                )
            ),
        )

    def test_python310(self):
        """Test something from Python 3.10 and make sure it fails.

        .pyc file taken from the python_decompiler project.
        """
        result = self.do_execution(
            entity_attrs={"file_format": self.FILE_FORMAT_OVERRIDE},
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "f9b6351131c9db9126804e88fa476d1863f785d2c1e342c7ebe74c7486384f28", "Python 3.10 pyc."
                    ),
                )
            ],
        )
        self.assertJobResult(
            result.get(self.MULTI_PLUGIN_KEY),
            JobResult(
                state=State(
                    State.Label.OPT_OUT,
                    failure_name="unsupported_python_version",
                    message=result.get(self.MULTI_PLUGIN_KEY).state.message,
                )
            ),
        )
        self.assertJobResult(
            result.get(self.MULTI_PLUGIN_KEY_SECONDARY),
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="f9b6351131c9db9126804e88fa476d1863f785d2c1e342c7ebe74c7486384f28",
                        data=[
                            EventData(
                                hash="2a2217e022529438237dfad09362df83643a87a67638efce2adfed9e44c5e05b",
                                label="text",
                            )
                        ],
                    )
                ],
                data={"2a2217e022529438237dfad09362df83643a87a67638efce2adfed9e44c5e05b": b""},
            ),
        )
