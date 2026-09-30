import argparse
import collections
import copy
import json
import pathlib
import typing

IDENTITY_FIELDS = (
    "VulnerabilityID",
    "PkgName",
    "InstalledVersion",
    "Severity",
)


def load_report(path: pathlib.Path) -> dict[str, typing.Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Invalid Trivy report {path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise SystemExit(f"Trivy report root must be an object: {path}")

    if payload.get("SchemaVersion") != 2:
        raise SystemExit(f"Unsupported Trivy SchemaVersion: {path}")

    results = payload.get("Results")
    if not isinstance(results, list):
        raise SystemExit(f"Trivy report Results must be a list: {path}")

    return payload


def vulnerability_identity(vulnerability: object) -> tuple[str, str, str, str]:
    if not isinstance(vulnerability, dict):
        raise SystemExit("Trivy vulnerability must be an object")

    values: list[str] = []

    for field in IDENTITY_FIELDS:
        value = vulnerability.get(field)

        if not isinstance(value, str) or not value.strip():
            raise SystemExit(f"Trivy vulnerability has invalid required field: {field}")

        normalized = value.strip()

        if field == "Severity":
            normalized = normalized.upper()

        values.append(normalized)

    return tuple(values)  # type: ignore[return-value]


def vulnerabilities_from_report(
    report: dict[str, typing.Any],
) -> list[object]:
    vulnerabilities: list[object] = []

    for index, result in enumerate(report["Results"]):
        if not isinstance(result, dict):
            raise SystemExit(f"Trivy result {index} must be an object")

        raw = result.get("Vulnerabilities", [])

        if not isinstance(raw, list):
            raise SystemExit(f"Trivy result {index} Vulnerabilities must be a list")

        vulnerabilities.extend(raw)

    return vulnerabilities


def build_delta(
    base_report: dict[str, typing.Any],
    candidate_report: dict[str, typing.Any],
) -> tuple[dict[str, typing.Any], dict[str, typing.Any]]:
    base_vulnerabilities = vulnerabilities_from_report(base_report)
    candidate_vulnerabilities = vulnerabilities_from_report(candidate_report)

    remaining_base = collections.Counter(
        vulnerability_identity(vulnerability) for vulnerability in base_vulnerabilities
    )

    delta_report = copy.deepcopy(candidate_report)

    inherited_count = 0
    delta_count = 0

    for result_index, result in enumerate(delta_report["Results"]):
        if not isinstance(result, dict):
            raise SystemExit(f"Trivy result {result_index} must be an object")

        raw_vulnerabilities = result.get("Vulnerabilities", [])

        if not isinstance(raw_vulnerabilities, list):
            raise SystemExit(f"Trivy result {result_index} Vulnerabilities must be a list")

        filtered: list[object] = []

        for vulnerability in raw_vulnerabilities:
            identity = vulnerability_identity(vulnerability)

            if remaining_base[identity] > 0:
                remaining_base[identity] -= 1
                inherited_count += 1
            else:
                filtered.append(vulnerability)
                delta_count += 1

        result["Vulnerabilities"] = filtered

    summary = {
        "schema_version": 1,
        "comparison_key": list(IDENTITY_FIELDS),
        "base_vulnerabilities": len(base_vulnerabilities),
        "candidate_vulnerabilities": len(candidate_vulnerabilities),
        "inherited_vulnerabilities": inherited_count,
        "delta_vulnerabilities": delta_count,
    }

    return delta_report, summary


def write_json(path: pathlib.Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a deterministic Trivy candidate-minus-base vulnerability report."
    )
    parser.add_argument("--base", required=True, type=pathlib.Path)
    parser.add_argument("--candidate", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--summary", required=True, type=pathlib.Path)
    args = parser.parse_args()

    base_report = load_report(args.base)
    candidate_report = load_report(args.candidate)

    delta_report, summary = build_delta(
        base_report,
        candidate_report,
    )

    write_json(args.output, delta_report)
    write_json(args.summary, summary)

    print(
        "TRIVY_BASE_DELTA "
        f"base={summary['base_vulnerabilities']} "
        f"candidate={summary['candidate_vulnerabilities']} "
        f"inherited={summary['inherited_vulnerabilities']} "
        f"delta={summary['delta_vulnerabilities']}"
    )


if __name__ == "__main__":
    main()
