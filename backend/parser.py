import json
import xmltodict #type: ignore


def parse_sbom(file):
    content = file.read().decode("utf-8")

    # ---------- JSON ----------
    try:
        data = json.loads(content)

        components = []

        # CycloneDX
        if "components" in data:
            components = data["components"]

        # SPDX JSON
        elif "packages" in data:
            components = data["packages"]

        # List format
        elif isinstance(data, list):
            components = data

        # package.json
        elif "dependencies" in data:
            deps = data.get("dependencies", {})

            for name, version in deps.items():
                clean_version = str(version).replace("^", "").replace("~", "")

                components.append({
                    "name": name,
                    "version": clean_version
                })

        if components:
            return normalize_flexible(components), "JSON"

    except Exception as e:
        print("JSON parsing failed:", e)

    # ---------- XML ----------
    try:
        data = xmltodict.parse(content)

        components = []

        if "bom" in data:
            bom = data["bom"]

            if "components" in bom:
                comps = bom["components"].get("component", [])

                if isinstance(comps, dict):
                    comps = [comps]

                components = comps

        if components:
            return normalize_flexible(components), "XML"

    except Exception as e:
        print("XML parsing failed:", e)

    # ---------- SPDX ----------
    try:
        lines = content.split("\n")
        components = []

        name = None

        for line in lines:
            if line.startswith("PackageName:"):
                name = line.split(":", 1)[1].strip()

            elif line.startswith("PackageVersion:"):
                version = line.split(":", 1)[1].strip()

                if name:
                    components.append({
                        "name": name,
                        "version": version
                    })

        if components:
            return components, "SPDX"

    except Exception as e:
        print("SPDX parsing failed:", e)

    # ❌ fallback
    raise Exception("Unsupported SBOM format")


def normalize_flexible(components):
    dependencies = []

    for comp in components:
        if not isinstance(comp, dict):
            continue

        name = (
            comp.get("name")
            or comp.get("package")
            or comp.get("PackageName")
        )

        version = (
            comp.get("version")
            or comp.get("versionInfo")
            or comp.get("PackageVersion")
        )

        if name and version:
            dependencies.append({
                "name": name,
                "version": version
            })

    return dependencies