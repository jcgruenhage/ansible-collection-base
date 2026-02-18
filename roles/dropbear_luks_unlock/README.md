# `famedly.base.dropbear_luks_unlock` ansible role

## Usage

- Specify authorized SSH keys in `dropbear_luks_unlock_authorized_keys: string[]`, which
  can then connect as `root@{host}` when dropbear is running.

- Specify the network configuration in `dropbear_luks_unlock_ip_config` as a dict with
  they keys `{ ip, gateway, netmask, hostname, interface }`. Currently, only
  static IPv4 config is tested.

- The default command to run on login in `/bin/cryptroot-unlock` - to override it, set `dropbear_luks_unlock_run_command` accordingly.

### Removal of SSH keys

- In order to remove pubkeys, the SSH keys specified in `dropbear_luks_unlock_authorized_keys`
  need to be dicts with a `key` and `state` key, where `state` is either `present`
  or `absent`.

- Ommitting the `state` for implicit `present` is allowed, so is plainly specifying
  the key as a string directly.

```yaml
dropbear_luks_unlock_authorized_keys:
  - key: "<ssh_key_0>"
  - key: "<ssh_key_1>"
    state: present
  - key: "<ssh_key_2>"
    state: absent
  - "<ssh_key_3>"
```

## Supported distros

- Tested and verified with stock debian 10
- Tested and verified with stock debian 11
