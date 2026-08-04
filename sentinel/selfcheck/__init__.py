"""Does Sentinel actually work right now?

Not "is the process running" — that question has answered `yes` during every
outage this project has had. It answered yes while the journald reader sat
frozen for 21 hours and SSH authentication went unwatched. It answered yes for a
full day while the nftables table did not exist and every block, manual or
automatic, would have failed silently.

So every check here asks whether a function is **producing its effect**:

    a collector       has written an event recently
    the detector      has consumed events recently
    the blocker       has a table in the kernel with the right sets in it
    the executor      answers
    the alerter       has actually delivered something

`systemctl is-active` is included, but as the weakest signal, not the verdict.
"""

from sentinel.selfcheck.checks import CheckResult, Status, run_all
from sentinel.selfcheck.runner import run_and_alert

__all__ = ["CheckResult", "Status", "run_all", "run_and_alert"]
