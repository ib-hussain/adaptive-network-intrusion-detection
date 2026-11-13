Ibrahim, **the university deployment is close to working.** The logs reveal two remaining blockers, both straightforward to address.

| Check                   | Status             |
| ----------------------- | ------------------ |
| GPU and CUDA            | &#x20;Working      |
| Python dependencies     | &#x20;Installed    |
| Unit tests              | &#x20;13/13 passed |
| Disk space              | &#x20;1.3 TB free  |
| Docker daemon           | &#x20;Running      |
| Docker user permissions | &#x20;Blocked      |
| Zeek                    | &#x20;Not found    |

## **1. Fix Docker permissions**

Your `sudo docker ps` succeeds, confirming that Docker itself works. Your regular account lacks permission to access `/var/run/docker.sock`.

**With university administrator approval**, run:

```
sudo usermod -aG docker "$USER"
newgrp docker
```

Docker's official procedure uses this approach, but note that membership in the `docker` group effectively grants root-level privileges.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://docs.docker.com\&sz=32)

Docker Docs



Now verify:

```
id -nG
docker ps
docker info >/dev/null && echo "Docker OK"
```

If these work, the Docker permission problem is resolved.

Do **not** use `sudo chmod 666 /var/run/docker.sock` or execute the whole experiment as root.

If the university does not permit Docker group membership, the lab administrator will need to provide an approved alternative.

## **2. Install Zeek**

First check whether Zeek is already installed outside your `PATH`:

```
ls -l /opt/zeek/bin/zeek
```

If it exists:

```
export PATH="/opt/zeek/bin:$PATH"
zeek --version
```

Otherwise, with administrator permission, use the official Zeek Ubuntu 24.04 packages:

```
sudo apt update
sudo apt install -y curl gnupg

echo 'deb https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list

curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg >/dev/null

sudo apt update
sudo apt install -y zeek-8.0

export PATH="/opt/zeek/bin:$PATH"
zeek --version
```

These installation instructions come from the [official Zeek documentation](https://docs.zeek.org/en/current/install.html?utm_source=chatgpt.com).&#x20;

[image](https://www.google.com/s2/favicons?domain=https://docs.zeek.org\&sz=32)

Book of Zeek (9.0.0)



## **3. Run the actual university pilot**

Once both `docker ps` and `zeek --version` succeed:

```
cd /home/fastlab/deepFakeDetection/adaptive-network-intrusion-detection

source .venv-cuda/bin/activate
```

If your environment was actually created as `.venv`, activate that instead.

Then:

```
export PATH="/opt/zeek/bin:$PATH"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1

./setup/university_check.sh
./setup/preflight.sh

sudo -v
./setup/university_pilot.sh --episodes 4 --capture
```

`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` prevents the unrelated ROS `launch_testing` plugin from being loaded automatically. This is preferable to repeatedly installing ROS dependencies into your research environment.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://pytest.org\&sz=32)

pytest documentation



**Note:** The correct flag is `--episodes`, not `--epsiodes`. The current pilot script does not implement `--help` or `-h`.

Once the four-episode pilot completes successfully, verify the generated PCAP and Zeek `conn.log`, then run:

```
./setup/university_pilot.sh --episodes 12 --capture
```

Do not launch the second run until the first capture and output validation have passed.

## **4. What if Zeek cannot be installed today?**

After fixing Docker permissions, you can still execute:

```
./setup/university_pilot.sh --episodes 4 --no-capture
```

This validates the Docker-based experiment and ML pipeline without independent packet capture. It is useful for troubleshooting, but **it does not satisfy our packet-level research validation requirement**.

## **5. Important for daily shutdowns**

Your 1.3 TB of free storage is more than sufficient for the planned experiments.

Completed runs will remain under:

- `src/data/raw/runs/`
- `outputs/results/`
- `outputs/figs/`
- `outputs/logs/zeek/`

Provided those directories are on persistent storage, they should survive shutdown.

However, an interrupted episode, an in-progress model fit, and the current game-controller state **still cannot resume from their exact previous state**. Continue using separate run IDs until we implement and verify checkpointing.

**Next action:** Fix Docker group access, install Zeek, and run `./setup/university_pilot.sh --episodes 4 --capture`. Send me that command's complete output. We'll use it to validate the network capture before expanding the research experiments.
