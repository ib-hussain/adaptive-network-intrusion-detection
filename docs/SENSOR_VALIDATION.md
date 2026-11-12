# Sensor validation gate before empirical claims

**The current gateway is an application-level observer, not a packet sensor.** Treat all gateway-derived results as only a functional proxy until independent Zeek PCAP collection is verified.

1. Verify both Compose networks are `internal: true`, no published ports, and neither a client nor a service has an external route. Don't infer isolation from YAML alone.
2. Place a packet sensor at a well-defined network interface/bridge and capture BOTH directions of the client-to-gateway and gateway-to-service connections. No privileged sensor is included by default; attaching one changes the security boundary and requires explicit operator setup.
3. Run one benign episode with known event count and correlate packet-level TCP connections, gateway app events and manifest timestamps. Count missing or duplicated observed conversations and explicitly record proxy traversal effects.
4. Run Zeek offline on captured PCAP using `setup/zeek_from_pcap.sh`. Verify JSON schema and numeric units; reject unrecognized source formats.
5. Compare per-episode Zeek flow counts, source/destination addresses, bytes, temporal ordering, and both flow directions against the experiment controller. A gateway request is not necessarily a 1:1 Zeek TCP connection (keep-alive/connection reuse can alter counts).
6. Check test positives before modelling: at least one verified incident with observed precursor windows in every split; for reliable science use MANY independent incidents per held-out family.
7. Freeze the experiment (versions, seeds, ports, software, topology, scenario schedule) and hash data files. Do not include the test set in game-policy feedback or hyperparameter tuning.
8. Create true behavioural-family and topology holdouts BEFORE conducting final evaluation. Independent random seeds of the same traffic profile are not adequate substitutes.

External references:
- https://docs.zeek.org/en/current/tutorial/logs.html
- https://docs.docker.com/compose/how-tos/networking/
