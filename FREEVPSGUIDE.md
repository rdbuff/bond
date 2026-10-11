# Free VPS guide: Oracle Cloud for Bond

This guide sets up a **free** server on Oracle Cloud's *Always Free* tier and
prepares it for Bond. No Linux knowledge needed: you click through Oracle's
website, then copy and paste three commands.

**Time:** about 30 minutes. **Cost:** free. Oracle asks for a card to verify
your identity, but the *Always Free* resources used here are never charged.

What you get for free:

| Resource | Always Free amount | What this guide uses |
|---|---|---|
| ARM server (Ampere A1) | up to 4 CPU cores and 24 GB of memory | 2 cores, 12 GB |
| Network speed | 1 Gbit/s per CPU core | 2 Gbit/s: plenty for Bond |
| Traffic | 10 TB out per month | |
| Disk | 200 GB total | the default 47 GB |

> Oracle changes its website from time to time. If a button has a slightly
> different name than here, look for the closest match.

---

## 1. Create your Oracle Cloud account

1. Go to **https://www.oracle.com/cloud/free/** and click **Start for free**.
2. Fill in your details and verify your email.
3. **Choose your Home Region carefully.** It can't be changed later, and your
   free server will live there. Pick the region **closest to where you
   live**: the closer the server, the lower the delay (ping) and the better
   Bond works.
4. Add a payment card for verification. Oracle may place a small temporary
   hold that is released again.
5. Wait for the "Your account is ready" email (usually a few minutes), then
   sign in at **https://cloud.oracle.com**.

---

## 2. Create the server

1. In the Oracle Cloud console, open the menu (☰, top left) →
   **Compute** → **Instances** → **Create instance**.
2. **Name:** anything, e.g. `bond`.
3. **Image and shape** → click **Edit**:
   - **Image** → **Change image** → **Ubuntu** → choose **Canonical Ubuntu
     24.04** (the normal one, not "Minimal") → **Select image**.
   - **Shape** → **Change shape** → **Virtual machine** → **Ampere** →
     tick **VM.Standard.A1.Flex**.
     Set **Number of OCPUs = 2** and **Memory = 12 GB** → **Select shape**.
     The page should say **"Always Free-eligible"** next to it.
4. **Networking**: leave the defaults. Oracle creates a new network
   ("virtual cloud network") with a **public subnet**. Make sure
   **Automatically assign public IPv4 address** is **on**.
5. **Add SSH keys** → choose **Generate a key pair for me** → click
   **Save private key**.

   > ⚠️ **Don't skip this.** The downloaded file (named like
   > `ssh-key-2026-10-11.key`) is the only way to log in to your server.
   > Keep it somewhere safe, for example in your Documents folder.

6. **Boot volume**: leave the defaults.
7. Click **Create**. After a minute or two the status turns green:
   **Running**.

### "Out of capacity for shape VM.Standard.A1.Flex"?

The free ARM servers are popular, so some regions run out. Try these, in
this order:

1. In step 3 of the form, try another **availability domain** (AD-1, AD-2,
   AD-3) if your region has more than one.
2. Use **1 OCPU and 6 GB** instead of 2 and 12. 1 OCPU still gives about
   1 Gbit/s, which is enough for most home connections.
3. Try again later: capacity comes and goes during the day.
4. Upgrade your account to **Pay As You Go** (☰ → **Billing & Cost
   Management** → **Upgrade and Manage Payment**). Always Free resources
   **stay free** after upgrading; you would only pay if you create
   resources *beyond* the free limits. Paid accounts get capacity much more
   easily, and their free servers are not reclaimed for being idle (see
   [Keeping your server](#7-keeping-your-server)).

> Don't use the tiny **VM.Standard.E2.1.Micro** (AMD) instead: it's also
> free, but its network is limited to about 50 Mbit/s, which is slower than
> most home connections.

---

## 3. Note the server's address

On your instance's page, under **Instance access** (or **Primary VNIC**),
find:

- **Public IPv4 address**, e.g. `203.0.113.10`. This is your **Relay
  server** address.
- **Username:** `ubuntu`

---

## 4. Open UDP port 51820

Oracle has a firewall around your server that blocks almost everything.
Bond needs **UDP port 51820** open.

1. On your instance's page, find **Primary VNIC** and click the **Subnet**
   link (it's called something like `subnet-2026...` or `public subnet-...`).
2. Open the **Security** tab (or **Security Lists**) and click the
   **Default Security List** for your network.
3. Open **Security rules** (or **Ingress Rules**) → **Add Ingress Rules**,
   and fill in:

   | Field | Value |
   |---|---|
   | Stateless | leave **unticked** |
   | Source Type | CIDR |
   | Source CIDR | `0.0.0.0/0` |
   | IP Protocol | **UDP** |
   | Source Port Range | leave empty |
   | Destination Port Range | **51820** |
   | Description | `Bond` |

4. Click **Add Ingress Rules**.

> **Important:** the rule must be on the security list of the subnet your
> server is **actually in**, the one you clicked in step 1. If your network
> has both a public and a private subnet, a rule on the private subnet's
> list does nothing for your server.

The server's *own* firewall (Oracle's Ubuntu image blocks forwarding by
default) is fixed automatically by Bond's install script in step 6.

---

## 5. Connect to the server from Windows

1. Open **PowerShell** (press the Windows key, type `PowerShell`, press Enter).
2. Windows refuses key files that other users could read, so first lock
   the key down. Replace the path with where you saved your key:

   ```
   icacls "$env:USERPROFILE\Documents\ssh-key-2026-10-11.key" /inheritance:r /grant:r "${env:USERNAME}:R"
   ```

3. Connect (use your key's path and your server's address):

   ```
   ssh -i "$env:USERPROFILE\Documents\ssh-key-2026-10-11.key" ubuntu@203.0.113.10
   ```

4. Type `yes` when it asks *"Are you sure you want to continue connecting?"*.

You're in when the line ends with something like `ubuntu@bond:~$`.

---

## 6. Install the Bond relay

Paste this whole line and press Enter:

```
curl -fsSL -o bond.tar.gz https://github.com/rdbuff/bond/releases/latest/download/bond-server-linux.tar.gz && tar -xzf bond.tar.gz && sudo sh bond-server/install.sh
```

It takes about a minute. At the end it prints:

```
Bond relay is running on UDP port 51820.
...
In the Bond app, open Settings and enter:
  Relay server: 203.0.113.10
  Server key:   q5T0...long text...k8=
```

Copy both values into the Bond app (**Settings** → **Relay server** and
**Server key** → **Save**), click the big switch, and you're done. 🎉

Type `exit` to leave the server. Show the key again any time by connecting
(step 5) and running `sudo cat /etc/bond/key`.

---

## 7. Keeping your server

- **Updating Bond's relay:** connect (step 5) and paste the same line from
  step 6 again. Your key is kept.
- **Idle reclamation:** Oracle may reclaim *Always Free* servers that sit
  almost unused (very low CPU, network and memory use) for a week. If you use
  Bond regularly this is unlikely. Upgrading to Pay As You Go (see the
  capacity section) prevents it entirely, and free resources stay free.
- **Security:** Oracle's Ubuntu image only allows logins with your key
  file, not passwords. Keep the key file and the Bond key private.
- **Restarting:** the relay starts by itself when the server boots.

---

## Troubleshooting

| Problem | What to do |
|---|---|
| **Out of capacity** when creating the server | See [the capacity section](#out-of-capacity-for-shape-vmstandarda1flex). |
| `ssh: ... UNPROTECTED PRIVATE KEY FILE` or `Permission denied (publickey)` | Run the `icacls` command from step 5 on your key file, and check you're using `ubuntu@` and the right key. |
| `ssh: connect to host ... Connection timed out` | Check the server's public IP and that it's **Running**. Port 22 (SSH) is open by default in the Default Security List; if you removed that rule, add it back (TCP, port 22). |
| Bond stays on **Connecting…** | The UDP 51820 rule (step 4) is missing, on the wrong subnet's list, or set to TCP. Also check the server address and key in Bond's Settings. |
| The install script says `unsupported CPU` | You created a non-ARM, non-x86 server; recreate it with the A1 shape. |
| Speed is lower than expected | Bond can't be faster than your two home connections combined. A region far away also adds delay. |

Still stuck? Open an issue on [GitHub](https://github.com/rdbuff/bond/issues).
