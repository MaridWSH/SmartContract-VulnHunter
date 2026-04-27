from vulnhunter.models.finding import FindingSeverity


def derive_severity(impact: int, likelihood: int) -> FindingSeverity:
    score = impact * likelihood
    if score >= 16:
        return FindingSeverity.CRITICAL
    if score >= 9:
        return FindingSeverity.HIGH
    if score >= 4:
        return FindingSeverity.MEDIUM
    return FindingSeverity.LOW
