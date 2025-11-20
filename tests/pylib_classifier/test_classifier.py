import unittest

from azul_plugin_python_decompiler.pylib_classifier import pylib_classifier


class TestClassifier(unittest.TestCase):
    def test_py2_mac(self):
        files = [
            "mmfparser.player.extensions.BinaryArray",
            "encodings.cp932",
            "Finder.Legacy_suite",
            "mmfparser",
            "xml.sax.expatreader",
            "twisted.python.win32",
            "mmfparser.player.event.actions.subapplication",
            "pyglet.libs.x11.xinerama",
            "encodings.euc_jis_2004",
            "email.quoprimime",
            "twisted.internet.ssl",
            "Carbon.Dialogs",
            "Carbon.AE",
            "os2emxpath",
            "rfc822",
            "zope.interface.declarations",
            "pyglet.gl.lib_agl",
            "Carbon.Windows",
            "StringIO",  # 2.7 package name and class same
            "unittest.main",
        ]
        classifier = pylib_classifier.PyLibClassifier(files)
        short_imports, long_imports = classifier.get_imports()
        self.assertEqual(
            short_imports,
            {
                "standard": [
                    "Carbon",
                    "StringIO",
                    "email",
                    "encodings",
                    "os2emxpath",
                    "rfc822",
                    "unittest",
                    "xml",
                ],
                "external": [
                    "Finder",
                    "mmfparser",
                    "pyglet",
                    "twisted",
                    "zope",
                ],
            },
        )
        self.assertEqual(
            long_imports,
            {
                "standard": [
                    "Carbon.AE",
                    "Carbon.Dialogs",
                    "Carbon.Windows",
                    "StringIO",
                    "email.quoprimime",
                    "encodings.cp932",
                    "encodings.euc_jis_2004",
                    "os2emxpath",  # why do these show up in long imports?
                    "rfc822",
                    "unittest.main",
                    "xml.sax.expatreader",
                ],
                "external": [
                    "Finder.Legacy_suite",
                    "mmfparser",
                    "mmfparser.player.event.actions.subapplication",
                    "mmfparser.player.extensions.BinaryArray",
                    "pyglet.gl.lib_agl",
                    "pyglet.libs.x11.xinerama",
                    "twisted.internet.ssl",
                    "twisted.python.win32",
                    "zope.interface.declarations",
                ],
            },
        )
