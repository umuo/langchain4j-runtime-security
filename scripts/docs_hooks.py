"""Publish the existing README and explicit example files without source copies."""
from pathlib import Path

from mkdocs.structure.files import File

ROOT = Path(__file__).resolve().parent.parent
# Keep this list explicit: deployment secrets must never be swept into the site.
EXAMPLES = (
    "demo.properties",
    "tool-demo.properties",
    "deployment-example.properties",
    "minimal.properties",
    "tool-policy-example.json",
    "context-tool-policy-example.json",
)


def on_files(files, config):
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    readme = readme.replace("](docs/", "](")
    files.append(File.generated(config, "overview.md", content=readme))
    for name in EXAMPLES:
        files.append(File.generated(
            config, f"config/{name}", content=(ROOT / "config" / name).read_bytes()
        ))
    return files


def on_page_markdown(markdown, page, config, files):
    # Existing docs link to ../config for GitHub; examples live inside the site.
    return markdown.replace("](../config/", "](config/")
