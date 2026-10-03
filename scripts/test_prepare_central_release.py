"""发布版本准备的反例测试：不接受不一致 reactor 或可注入版本输入。"""
import tempfile
import unittest
from pathlib import Path

from prepare_central_release import GROUP, MODULES, prepare


class PrepareReleaseTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.joinpath("pom.xml").write_text(
            '<project xmlns="http://maven.apache.org/POM/4.0.0">'
            f'<groupId>{GROUP}</groupId><version>0.1.0-SNAPSHOT</version><modules>'
            + ''.join(f'<module>{name}</module>' for name in MODULES)
            + '</modules></project>', encoding="utf-8")
        for name in MODULES:
            directory = self.root / name
            directory.mkdir()
            directory.joinpath("pom.xml").write_text(
                '<project xmlns="http://maven.apache.org/POM/4.0.0"><parent>'
                f'<groupId>{GROUP}</groupId><version>0.1.0-SNAPSHOT</version>'
                f'</parent><artifactId>{name}</artifactId></project>', encoding="utf-8")

    def contents(self):
        return {str(path.relative_to(self.root)): path.read_bytes()
                for path in self.root.rglob("pom.xml")}

    def test_updates_all_parent_versions(self):
        self.assertEqual("0.1.0-SNAPSHOT", prepare(self.root, "0.1.0-alpha.1"))
        for text in self.contents().values():
            self.assertIn(b"<version>0.1.0-alpha.1</version>", text)
            self.assertNotIn(b"SNAPSHOT", text)

    def test_accepts_stable_and_prerelease_versions(self):
        for version in ("0.1.0", "1.2.3-beta.2", "2.0.0-rc.1"):
            with self.subTest(version=version):
                prepare(self.root, version)

    def test_rejects_invalid_versions_without_writes(self):
        before = self.contents()
        for version in ("0.1.0-SNAPSHOT", "v0.1.0", "01.2.3", "1.2", "1.2.3;whoami",
                        "1.2.3\n", "1.2.3+build", "1.2.3-alpha.01", "1.2.3/../../x"):
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    prepare(self.root, version)
                self.assertEqual(before, self.contents())

    def test_inconsistent_last_module_does_not_partially_update(self):
        path = self.root / MODULES[-1] / "pom.xml"
        path.write_text(path.read_text().replace("0.1.0-SNAPSHOT", "0.2.0-SNAPSHOT"))
        before = self.contents()
        with self.assertRaises(ValueError):
            prepare(self.root, "0.1.0")
        self.assertEqual(before, self.contents())

    def test_unknown_namespace_rejected_without_writes(self):
        path = self.root / "pom.xml"
        path.write_text(path.read_text().replace(GROUP, "io.other"))
        before = self.contents()
        with self.assertRaises(ValueError):
            prepare(self.root, "0.1.0")
        self.assertEqual(before, self.contents())

    def test_module_scope_change_requires_review(self):
        path = self.root / "pom.xml"
        path.write_text(path.read_text().replace("<module>demo</module>", ""))
        before = self.contents()
        with self.assertRaises(ValueError):
            prepare(self.root, "0.1.0")
        self.assertEqual(before, self.contents())

    def test_explicit_child_version_requires_review(self):
        path = self.root / MODULES[0] / "pom.xml"
        path.write_text(path.read_text().replace("</project>", "<version>0.2.0</version></project>"))
        before = self.contents()
        with self.assertRaises(ValueError):
            prepare(self.root, "0.1.0")
        self.assertEqual(before, self.contents())


if __name__ == "__main__":
    unittest.main()
