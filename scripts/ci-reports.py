#!/usr/bin/env python3
"""Keep JUnit results without archiving response bodies or arbitrary test output."""

from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def sanitize(root):
    for parent in root.iter():
        for child in list(parent):
            if child.tag in {"system-out", "system-err", "properties"}:
                parent.remove(child)
            elif child.tag in {"failure", "error", "skipped"}:
                child.clear()
                child.set("message", "See the GitHub Actions job log for details")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        root = ET.fromstring(
            '<testsuite tests="1" failures="1"><properties>SECRET</properties>'
            '<testcase name="authorization"><failure message="SECRET">SECRET</failure>'
            '<system-out>SECRET</system-out><system-err>SECRET</system-err>'
            '<skipped message="SECRET"/></testcase></testsuite>'
        )
        sanitize(root)
        assert "SECRET" not in ET.tostring(root, encoding="unicode")
        assert root.get("failures") == "1"
        assert root.find("testcase/failure") is not None
        assert root.find("testcase").get("name") == "authorization"
    elif sys.argv[1:]:
        sys.exit("Usage: python3 scripts/ci-reports.py [--self-test]")
    else:
        for path in Path("reports").glob("*.xml"):
            tree = ET.parse(path)
            sanitize(tree.getroot())
            tree.write(path, encoding="utf-8", xml_declaration=True)
