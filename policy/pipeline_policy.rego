package devsecops.gating

import future.keywords.if

default allow := false

# The build passes ONLY if there are zero "Critical" vulnerabilities
# and no blacklisted licenses (e.g., AGPL)
allow if {
    count(critical_vulns) == 0
    not has_blacklisted_license
}

critical_vulns := [v | 
    v := input.vulnerabilities[_]
    v.severity == "Critical"
]

has_blacklisted_license if {
    input.artifacts[_].licenses[_] == "AGPL-3.0"
}
