**We have made progress, but the pilot is not yet confirmed complete.** The line

```
/out/runs/pilot_20261113T083155Z_61354/episodes.jsonl
```

means the traffic generator reached its final output statement. It does not mean the complete pipeline has finished.

I inspected the actual deployment script. With `--episodes 4`, it should generate **32 episodes and 384 HTTP requests** across the four policies. Thirty minutes of silence after that output is abnormal.

One likely cause is the packet-capture shutdown code: it signals the background `sudo` process and then waits for it. If the underlying `tcpdump` process does not exit, the script can remain blocked.

## **1. Check the running experiment**

Open a **second terminal**, leaving the original running for now, and execute:

```
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection

RUN=pilot_20261113T083155Z_61354

wc -l "src/data/raw/runs/$RUN/episodes.jsonl"
ls -lh "src/data/raw/runs/$RUN/"
docker compose ps -a
ps -eo pid,ppid,stat,etime,args | grep -E '[t]cpdump|[u]niversity_pilot|[d]ocker compose|[s]rc.code.pipeline'
```

If the manifest contains 32 records, the runner container has exited, and `tcpdump` remains active, that strongly supports the capture-shutdown diagnosis.

**Do not delete the PCAP or restart the entire experiment.** The existing data may be recoverable without recollection.

## **2. Recover the current run without losing its data**

If the check confirms that the runner has finished but `tcpdump` is still recording, identify the actual capture process:

```
sudo pgrep -a -x tcpdump
```

Find the entry containing:

```
pilot_20261113T083155Z_61354/traffic.pcap
```

Stop **only that process**, replacing `PID` with its actual number:

```
sudo kill -INT PID
```

This requests a graceful capture stop. The original script may then continue with model evaluation and Zeek processing.

Be aware that your original command contains `&&` followed by 12- and 24-episode runs. **If the four-episode run completes successfully, those commands will launch automatically.** I recommend cancelling that queued sequence and using the corrected launcher instead.

## **3. Corrected deployment and recovery package**

I have prepared and locally tested a recovery patch.

**Phase 3 Pilot Recovery Patch**

Download ZIP

Recovery script, corrected pilot launcher, and instructions

Once the original pilot process and capture have stopped, copy the ZIP to the university machine and install it in your project directory:

```
unzip -n ~/Downloads/Phase3_Pilot_Recovery_Patch.zip -d .
chmod +x setup/university_{finish_existing,pilot_v2}.sh
```

If the original run stopped before completing its remaining processing, recover the existing observations:

```
./setup/university_finish_existing.sh pilot_20261113T083155Z_61354
```

This does not regenerate traffic or overwrite your raw recordings. It completes gateway-data extraction, baseline evaluation, output validation, and available Zeek processing.

Recovery code tested against 32 completed loopback episodes and 384 observed requests. The revised Docker capture shutdown still requires validation on Ubuntu.

## **4. Expanding the experiment**

Once we have a successfully completed four-episode run, use the corrected launcher:

```
./setup/university_pilot_v2.sh --episodes 12 --capture
```

I would **not launch the 24-episode run yet**. The present generator reuses a fixed seed, the same three traffic profiles, and one topology. More repetitions will not establish generalisation to unseen network behaviours.

Our next meaningful development targets are:

1. Validate the recorded PCAP against Zeek `conn.log` and the experiment manifest.
2. Introduce genuinely distinct, time-separated incident stages and richer benign network traffic.
3. Make the scenario-game state and training recoverable after shutdown.
4. Implement independent scenario/topology holdouts and temporal-network modelling.
5. Perform matched fixed/random/strategic comparisons, measuring valid \\(T\_{\text{lead}}\\), detection recall, and false alarms.

Also, while your project filesystem has 1.3 TB free, Docker's root filesystem has only **17 GB free**. Avoid unnecessary image downloads; retain experiment data on the larger project filesystem.

**Current verdict:** The traffic-generation stage appears to have finished. We need to resolve the possible capture-shutdown hang and validate its outputs before treating the experiment as successful or scaling it.
