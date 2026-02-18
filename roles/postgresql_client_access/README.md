# `famedly.base.postgresql_client_access` ansible role for configuring users, databases and pg_hba entries of an PostgreSQL instance
This convenience role creates and updates users, databases and pg_hba entries.
It's designed to work with PostgreSQL servers running inside a docker container deployed by [famedly.base.postgresql](https://github.com/famedly/ansible-collection-base/tree/main/roles/postgresql).

## Requirements
- psycopg2

## Role Variables
See `defaults/main.yml`.

The `postgresql_superuser_password` variable must contain the password for the default user `postgres` if the authentication method in `pg_hba.conf` is not `trust`.

When `postgresql_client_access_connect_socket` is set to `true`, the role tries to connect to the server via UNIX socket specified in `postgresql_client_access_socket_path`.
If it is set to `false`, the connection will be established via TCP socket. If `postgresql_host_port` is set, it will try to connect to this port on `127.0.0.1`, otherwise it will try to find out the container's IP and connect to it on the standard port `5432`.

### `postgresql_client_access_users` list
Here you specify the users you want present or absent. The following features from the [postgresql_user module](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_user_module.html) are supported:

```yaml
postgresql_client_access_users:
  - name: user1
    password: "{{ vault_user1_postgresql_password }}"
  - name: user2
    state: absent  # defaults to present
```

### `postgresql_client_access_databases` list
Here you specify the database you want to be present or absent. The following features from the [postgresql_db module](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_db_module.html) are supported:

```yaml
postgresql_client_access_databases:
  - name: db1
    owner: user1
    lc_collate: "en_US.utf8"  # defaults to 'C'
    lc_ctype: "en_US.utf8"  # defaults to 'C'
  - name: db2
    state: absent  # defaults to present, only present and absent supported
```

### `postgresql_client_access_databases` list
Here you specify the pg_hba entries you want to be present or absent. The following features from the [postgresql_pg_hba module](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_pg_hba_module.html) are supported:

```yaml
postgresql_client_access_hba_entries:
  - contype: local
    databases: db1
    users: user1
    method: trust
  - contype: host
    databases: "db1,db2"
    users: user2
    method: md5
    address: "172.17.0.0/16"
    state: absent
```

## Dependencies
Docker needs to be installed and configured.

## Example Playbook
```yaml
---
- name: Configure db1 for user1
  hosts: [ all ]
  become: true
  roles:
    - famedly.base.postgresql_client_access
  vars:
    postgresql_client_access_users:
      - name: user1
        password: "{{ vault_user1_postgresql_password }}"
    postgresql_client_access_databases:
      - name: db1
        owner: user1
    postgresql_client_access_hba_entries:
      - contype: local
        databases: db1
        users: user1
        method: trust
    postgresql_host_port: "2345"
    postgresql_superuser_password: "{{ vault_postgresql_superuser_password }}"
    postgresql_client_access_connect_socket: "false"
```

## License
GNU Affero General Public License v3

## Author Information
Famedly GmbH, famedly.de
