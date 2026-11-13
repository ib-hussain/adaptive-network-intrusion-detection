# University pilot: capture-stop correction and post-processing recovery

**Applies to the Phase 3 University Deployment Kit already installed.** Does not overwrite existing `university_pilot.sh` or any raw, processed, model, or experiment data.

## Why the first command may appear hung

After the runner prints `/out/runs/RUN_ID/episodes.jsonl`, Python has returned its manifest path, but the wrapper script must still finish Docker `run --rm`/`tee`, stop tcpdump, extract matching gateway events, train six baseline-policy combinations, validate outputs, and generate Zeek logs. The original stop routine signalled the `sudo` wrapper PID, not necessarily the real `tcpdump` PID, and could wait indefinitely. A stopped runner is not proof of a completed pilot.

## Diagnose in a **second** terminal

```bash
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection
RUN=pilot_20261113T083155Z_61354
wc -l "src/data/raw/runs/$RUN/episodes.jsonl"
ls -lh "src/data/raw/runs/$RUN/"
docker compose ps -a
ps -eo pid,ppid,stat,etime,args | grep -E '[t]cpdump|[u]niversity_pilot|[d]ocker compose|[s]rc.code.pipeline'
```

For `--episodes 4`, expect **32** complete manifest records and **384** HTTP gateway records. Identify *which command is still running* first. If and only if `tcpdump` for that run remains active and the runner has exited, identify its real PID from the `ps` output and terminate that specific capture gracefully: `sudo kill -INT ACTUAL_TCPDUMP_PID`. Never signal the `sudo` wrapper blindly, run `pkill tcpdump`, kill unrelated captures, or delete raw files. If necessary use `Ctrl+C` to stop the current shell's queued `&&` commands, then separately stop the correct capture process and recover from the saved records.

## Recover a complete collected run

After capture has been stopped and the original pilot process is no longer active, install this patch into the repository with `unzip -n <zip> -d .` and run:

```bash
./setup/university_finish_existing.sh pilot_20261113T083155Z_61354
```

This command checks **all eight policy/condition groups**, verifies incident time ordering, extracts exactly the matching gateway records if needed, reruns the baseline analysis in a **new** results directory, and converts a captured PCAP to Zeek JSON logs if available. It does not regenerate traffic. An incomplete or duplicated gateway log fails validation, and original raw data are never overwritten. It does not reconcile Zeek flow labels: independent sensor alignment is still required.

## Future pilot with more reliable capture process handling

Use the **new** `university_pilot_v2.sh` rather than overwriting the existing script:

```bash
chmod +x setup/university_{finish_existing,pilot_v2}.sh
./setup/university_pilot_v2.sh --episodes 4 --capture
```

Changes: `--help` support; noninteractive Compose runner (`-T`); process-specific PID record inside the root capture process; stop attempts on the verified child `tcpdump` PID with bounded wait and fallback. This is a safeguard against a known plausible hang, **not proof** that all hangs are fixed. Verify one successful run including `conn.log` and a coherent PCAP before larger experiments.

## Scientific caution

Increasing `--episodes` collects more repetitions of **harmless HTTP traffic profiles**, not malware or validated network intrusion classes. Current incident milestone timing is the final dummy HTTP request, typically less than a few seconds from onset. Results are a pilot of a software pipeline, not valid real-world early-warning lead time or unseen-topology generalisation. Next research work should validate Zeek-to-manifest alignment and build distinct, time-separated benign and staged incident profiles and additional topologies before scaling collection.
