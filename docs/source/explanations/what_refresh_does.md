# What refresh does

When you run the `ua refresh` command on your machine, three distinct stages are performed:

* **contract**: The contract information on the machine is refreshed. If we find any deltas
  between the old contract and the new one, we process that delta and apply the changes
  on the machine. If you need only this stage during refresh, run `ua refresh contract`.

* **config**: If there is any config change made on `/etc/ubuntu-advantage/uaclient.conf`, those
  changes will now be applied to the machine. If you need only this stage during refresh, run `ua refresh config`.

* **MOTD and APT messages**: UA process new MOTD and APT messages and refresh the machine to use
  them. If you need only this stage during refresh, run `ua refresh messages`.
