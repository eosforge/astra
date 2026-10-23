"""Verify maintained Markdown destinations and bilingual README navigation without network requests."""

import re
from pathlib import Path
import unittest
from urllib.parse import unquote, urlsplit

from tools import verify as v

ROOT = Path(__file__).resolve().parents[1]


def prose(path: Path) -> str:
    """Remove fenced examples so template links are not mistaken for actual navigation."""
    text = path.read_text(encoding="utf-8")
    return re.sub(r"(?ms)^\s*(```|~~~).*?^\s*\1[^\n]*$", "", text)


def anchors(text: str) -> set[str]:
    """Reproduce explicit HTML anchors and ordinary GitHub heading slugs, including duplicate suffixes."""
    result = set(re.findall(r'<a\s+(?:id|name)="([^"]+)"', text))
    duplicates = {}
    for heading in re.findall(r"(?m)^#{1,6}\s+(.+?)\s*#*\s*$", text):
        slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        number = duplicates.get(slug, 0)
        duplicates[slug] = number + 1
        result.add(slug if number == 0 else f"{slug}-{number}")
    return result


class DocumentationTests(unittest.TestCase):
    """Check all owned Markdown, retaining every actual link in the assertion denominator."""

    def documents(self) -> list[Path]:
        """Select current maintained input paths, excluding generated/frozen/ignored source by configured ownership."""
        config = v.decode(v.read(ROOT / "development.json"))
        source = v.source(ROOT)
        inventory = v.inventory(config, [item["path"] for item in source["files"] if item["sha256"] is not None])
        return sorted(ROOT / name for files in inventory["components"].values() for name in files if name.endswith(".md"))

    def test_links(self) -> None:
        """Every local navigation target and named fragment resolves in the maintained checkout."""
        count = 0
        for path in self.documents():
            for raw in re.findall(r"(?<!!)\[[^\]\n]*\]\(([^)\n]+)\)", prose(path)):
                target = raw.strip().split(' "', 1)[0].strip("<>")
                parsed = urlsplit(target)
                if parsed.scheme or target.startswith("//"):
                    continue
                destination = (path.parent / unquote(parsed.path)).resolve() if parsed.path else path
                with self.subTest(document=path.relative_to(ROOT), target=target):
                    self.assertTrue(destination.is_relative_to(ROOT), "Local documentation navigation escapes the maintained Astra root")
                    self.assertTrue(destination.exists(), "Missing local documentation target")
                    if parsed.fragment and destination.suffix == ".md":
                        self.assertIn(unquote(parsed.fragment), anchors(destination.read_text(encoding="utf-8")))
                count += 1
        self.assertGreater(count, 0, "Empty navigation inventory")

    def test_readmes(self) -> None:
        """Each existing Chinese README and English companion link to one another."""
        for path in self.documents():
            if path.name != "README_CN.md":
                continue
            english = path.with_name("README.md")
            with self.subTest(document=path.relative_to(ROOT)):
                self.assertTrue(english.is_file())
                self.assertIn("README_CN.md", prose(english))
                self.assertIn("README.md", prose(path))


if __name__ == "__main__":
    unittest.main()
