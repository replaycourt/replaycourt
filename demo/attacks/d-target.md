---
id: attack-d-target
title: "Report in the second program (target for the stolen-key demo)"
---

# Target report

This report exists only so that the program judged by another verifier has a submission. The
stolen-key demo (`d-stolen-key.ts`) tries to post a verdict on it with the first verifier's
function-call key; the contract must refuse. The hunter withdraws it after the pending timeout.
