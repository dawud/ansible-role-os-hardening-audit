# Audit daemon (auditd) hardening

Follows the [upstream documentation](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/chap-system_auditing.html).
Includes tunable settings to comply with OSPP.
Includes PCI-DSS V3.1 ruleset.

These two blog posts provide a nice intro into the audit system:

- [Brief introduction to auditd](https://secopsmonkey.com/a-brief-introduction-to-auditd.html)
- [Auditd by example](https://secopsmonkey.com/auditd-by-example-tracking-file-changes.html)

## Requirements

None. The required packages are managed by the role.
Possible integrations and extensions include:

- [Splunk integration](https://github.com/doksu/splunk_auditd)
- [audisp plugin for CEF format audit message forwarding](https://github.com/gdestuynder/audisp-cef)

## Role Variables

- From `defaults/main.yml`

```yml
# Set the package install state for distribution packages
# Options are 'present' and 'latest'
security_package_state: present
# Send audit records to a different system using audisp.
# security_audisp_remote_server: '10.0.21.1'                  # V-72083
# Encrypt audit records when they are transmitted over the network.
# security_audisp_enable_krb5: 'yes'                            # V-72085
# Set the auditd failure flag. WARNING: READ DOCUMENTATION BEFORE CHANGING!
security_rhel7_audit_failure_flag: 1                         # V-72081
# Set the action to take when the disk is full or network events cannot be sent.
security_rhel7_auditd_disk_full_action: syslog               # V-72087
security_rhel7_auditd_network_failure_action: syslog         # V-72087
# Size of remaining disk space (in MB) that triggers alerts.
#security_rhel7_auditd_space_left: >
#  {%- if 'docker' not in ansible_virtualization_type | default('False') | bool %}
#  {{ (ansible_mounts | selectattr('mount', 'equalto', '/') | map(attribute='size_total') | first * 0.25 / 1024 / 1024) | int }}
#  {# V-72089 #}
#  {%- else %}
#  500
#  {%- endif %}
security_rhel7_auditd_space_left: 500
# Action to take when the space_left threshold is reached.
security_rhel7_auditd_space_left_action: email               # V-72091
# Send auditd email alerts to this user.
security_rhel7_auditd_action_mail_acct: root                 # V-72093

# Add dont-audit rules for commands/syscalls.
security_rhel7_audit_dont_audit_cron: 'yes'
security_rhel7_audit_dont_audit_chrony: 'yes'
security_rhel7_audit_dont_audit_crypto_key_user: 'yes'

# Add audit rules for grouped syscalls.
security_rhel7_audit_file_deletion_events_by_user: 'yes'
security_rhel7_audit_unauthorized_creation_attempts_to_files: 'yes'
security_rhel7_audit_unauthorized_modification_attempts_to_files: 'yes'
security_rhel7_audit_unsuccessul_delete_attempts_to_files: 'yes'
security_rhel7_audit_unsuccessul_permission_changes_to_files: 'yes'
security_rhel7_audit_unsuccessul_ownership_changes_to_files: 'yes'
security_rhel7_audit_unauthorized_access_attempts_to_files: 'yes'

# Add audit rules for privileged commands
security_rhel7_audit_privileged_commands: 'yes'                # V-72149
security_rhel7_audit_at: 'yes'                                 # FAU_GEN.1.1.c
security_rhel7_audit_chage: 'yes'                              # V-72155
security_rhel7_audit_chsh: 'yes'                               # V-72167
security_rhel7_audit_chcon: 'yes'                              # V-72139
security_rhel7_audit_crontab: 'yes'                            # V-72183
security_rhel7_audit_delete_module: 'yes'                      # V-72189
security_rhel7_audit_gpasswd: 'yes'                            # V-72153
security_rhel7_audit_init_module: 'yes'                        # V-72187
security_rhel7_audit_mount: 'yes'                              # V-72171
security_rhel7_audit_newgidmap: 'yes'                          # FAU_GEN.1.1.c
security_rhel7_audit_newgrp: 'yes'                             # V-72165
security_rhel7_audit_newuidmap: 'yes'                          # FAU_GEN.1.1.c
security_rhel7_audit_pam_timestamp_check: 'yes'                # V-72185
security_rhel7_audit_passwd: 'yes'                             # V-72149
security_rhel7_audit_postdrop: 'yes'                           # V-72175
security_rhel7_audit_postqueue: 'yes'                          # V-72177
security_rhel7_audit_pt_chown: 'yes'                           # V-72181
security_rhel7_audit_restorecon: 'yes'                         # V-72141
security_rhel7_audit_rmdir: 'yes'                              # V-72203
security_rhel7_audit_semanage: 'yes'                           # V-72135
security_rhel7_audit_setsebool: 'yes'                          # V-72137
security_rhel7_audit_seunshare: 'yes'                          # V-72111
security_rhel7_audit_ssh_keysign: 'yes'                        # V-72179
security_rhel7_audit_su: 'yes'                                 # V-72159
security_rhel7_audit_sudo: 'yes'                               # V-72161
security_rhel7_audit_sudoedit: 'yes'                           # V-72169
security_rhel7_audit_umount: 'yes'                             # V-72173
security_rhel7_audit_unix_chkpwd: 'yes'                        # V-72151
security_rhel7_audit_userhelper: 'yes'                         # V-72157
security_rhel7_audit_usernetctl: 'yes'                         # FAU_GEN.1.1.c

# Add audit rules for other events.
security_rhel7_audit_account_access: 'yes'                     # V-72143
security_rhel7_audit_sudo_config_changes: 'yes'                # V-72163
security_rhel7_audit_insmod: 'yes'                             # V-72191
security_rhel7_audit_rmmod: 'yes'                              # V-72193
security_rhel7_audit_modprobe: 'yes'                           # V-72195
security_rhel7_audit_account_actions: 'yes'                    # V-72197
security_rhel7_audit_32bit: 'yes'
security_rhel7_audit_log_access_modifications: 'yes'           # FAU_GEN.1.1.c
```

- From `vars/main.yml`

`auditd_config`
This variable is used in tasks/main.yml to configure auditd and audisp

Each dictionary has this structure:

```yml
  command: the command/syscall to audit (required)
  stig_id: the number/ID from the STIG (required)
  arch_specific: 'yes' if the rule depends on the architecture type,
                 otherwise 'no' (required)
  path: the path to the command (optional, default is '/usr/bin')
  distro: restrict deployment to a single Linux distribution (optional,
          should be equal to 'ansible_os_family | lower', such as 'redhat'
```

```yml
auditd_config:
  - parameter: disk_full_action
    value: "{{ security_rhel7_auditd_disk_full_action }}"
    config: /etc/audisp/audisp-remote.conf
  - parameter: network_failure_action
    value: "{{ security_rhel7_auditd_network_failure_action }}"
    config: /etc/audisp/audisp-remote.conf
  - parameter: space_left
    value: "{{ security_rhel7_auditd_space_left }}"
    config: /etc/audit/auditd.conf
  - parameter: space_left_action
    value: "{{ security_rhel7_auditd_space_left_action }}"
    config: /etc/audit/auditd.conf
  - parameter: action_mail_acct
    value: "{{ security_rhel7_auditd_action_mail_acct }}"
    config: /etc/audit/auditd.conf
```

`audited_commands`
This variable is used in tasks/main.yml to deploy auditd rules
for various commands and syscalls.

Each dictionary has this structure:

```yml
  command: the command/syscall to audit (required)
  path: the path to the command (optional, default is '/usr/bin')
  auid: value for audit
  distro: restrict deployment to a single Linux distribution (optional,
          should be equal to 'ansible_os_family | lower', such as 'redhat'
```

```yml
audited_commands:
  - command: chsh
```

## Dependencies

None.

## Example Playbook

Example of how to use this role:

```yml
    - hosts: servers
      roles:
         - { role: ansible-os-hardening-audit }
```

## Contributing

This repository uses
[git-flow](http://nvie.com/posts/a-successful-git-branching-model/).
To contribute to the role, create a new feature branch (`feature/foo_bar_baz`),
write [Molecule](http://molecule.readthedocs.io/en/master/index.html) tests for
the new functionality
and submit a pull request targeting the `develop` branch.

Happy hacking!

## License

Apache 2.0, as this work is derived from [OpenStack's ansible-hardening role](https://github.com/openstack/ansible-hardening).

## Author Information

[David Sastre](david.sastre@redhat.com)
