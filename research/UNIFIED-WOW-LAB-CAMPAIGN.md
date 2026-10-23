# Unified WOW/LABO campaign — controlled CI

The parallel laboratory grid runs five existing EXP-020 / TIME-01–04 / CAUSAL-01 datasets on fresh hosted runners. This is a RE-RUN and integration regression sweep, not a new physical experiment.

The WOW codebase runs a separate seven-job campaign for real W3/W8/W9/W10/W12/W13/W14 primitives, crash testing and QUIC loopback. Cross-repository workflows run independently because the source code lives in distinct repos.

Acceptance: GitHub Actions success for all jobs, expected JSON/CSV artifacts, test logs. Failure of any job means the campaign is not accepted. Unknown and unavailable time are fail-closed outcomes.

Not tested in Actions: real power failure, hardware RTC, physical separation, network partitions across independently owned machines, high-availability long-duration operation, 1000 real custodians, actual production STORE/FETCH capability enforcement, true operator independence, ability to detect hidden forged events, and privacy analysis of cross-scope transcript observations. Do not infer safety for production from green CI.
