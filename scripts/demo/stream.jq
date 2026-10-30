# One line per event: time, severity, category, summary and the rule that
# matched, if any. Colors by severity.
def color: {"critical": "\u001b[1;37;41m", "high": "\u001b[1;31m", "medium": "\u001b[33m", "low": "\u001b[36m"}[.] // "";
"\u001b[2m\(.time[11:19])\u001b[0m  \(.severity | color)\(.severity | ascii_upcase | . + "        " | .[0:8])\u001b[0m  \u001b[1;36m\(.category)\u001b[0m  \(.summary)"
+ (.rule.id as $r | if $r and (.summary | contains($r) | not) then "  \u001b[2;35m[\($r)]\u001b[0m" else "" end)
