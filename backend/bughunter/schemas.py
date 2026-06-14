"""Finding model + the JSON schema Claude is constrained to."""
from typing import Literal, Optional
from pydantic import BaseModel

Category = Literal["Security", "Logic"]
Severity = Literal["Critical", "High", "Medium", "Low"]
Confidence = Literal["High", "Medium", "Low"]

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


class Finding(BaseModel):
    file: str
    category: Category
    severity: Severity
    title: str
    line: int  # 0 = file-level / not line-specific
    description: str
    recommendation: str
    confidence: Confidence


# Constrains Claude's response (output_config.format). Objects must set
# additionalProperties:false and list required fields. `file` is added by us
# afterwards, so it is not part of the model's schema.
FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "category": {"type": "string", "enum": ["Security", "Logic"]},
                    "severity": {
                        "type": "string",
                        "enum": ["Critical", "High", "Medium", "Low"],
                    },
                    "title": {"type": "string", "description": "short headline"},
                    "line": {
                        "type": "integer",
                        "description": "1-based line number, or 0 if file-level",
                    },
                    "description": {
                        "type": "string",
                        "description": "what the bug is and why it matters",
                    },
                    "recommendation": {
                        "type": "string",
                        "description": "concrete fix",
                    },
                    "confidence": {
                        "type": "string",
                        "enum": ["High", "Medium", "Low"],
                    },
                },
                "required": [
                    "category", "severity", "title", "line",
                    "description", "recommendation", "confidence",
                ],
                "additionalProperties": False,
            },
        },
    },
    "required": ["findings"],
    "additionalProperties": False,
}


class ScanSummary(BaseModel):
    root: str
    files_scanned: int
    files_skipped: int
    total_findings: int
    by_severity: dict[str, int]
    by_category: dict[str, int]


class ScanResult(BaseModel):
    summary: ScanSummary
    findings: list[Finding]
