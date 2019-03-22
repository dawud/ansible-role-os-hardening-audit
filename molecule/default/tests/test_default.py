import os

import pytest

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


@pytest.mark.parametrize("name,version", [
    ("audispd-plugins", "2.6.5"),
    ("audit", "2.6.5"),
    ("audit-libs", "2.6.5"),
    ("audit-libs-python", "2.6.5")
])
def test_audit_packages(host, name, version):
    pkg = host.package(name)
    assert pkg.is_installed
    assert pkg.version.startswith(version)


def test_audit_configuration_file(host):
    f = host.file('/etc/audit/auditd.conf')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o640
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('local_events = yes')
    assert f.contains('write_logs = yes')
    assert f.contains('log_file = /var/log/audit/audit.log')
    assert f.contains('log_group = root')
    assert f.contains('log_format = RAW')
    assert f.contains('flush = INCREMENTAL_ASYNC')
    assert f.contains('freq = 100')
    assert f.contains('max_log_file = 8')
    assert f.contains('num_logs = 5')
    assert f.contains('priority_boost = 4')
    assert f.contains('disp_qos = lossy')
    assert f.contains('dispatcher = /sbin/audispd')
    assert f.contains('name_format = NONE')
    assert f.contains('max_log_file_action = KEEP_LOGS')
    assert f.contains('space_left =')
    assert f.contains('space_left_action = email')
    assert f.contains('action_mail_acct = root')
    assert f.contains('admin_space_left = 50')
    assert f.contains('admin_space_left_action = SUSPEND')
    assert f.contains('disk_full_action = SUSPEND')
    assert f.contains('disk_error_action = SUSPEND')
    assert f.contains('use_libwrap = yes')
    assert f.contains('tcp_listen_queue = 5')
    assert f.contains('tcp_max_per_addr = 1')
    assert f.contains('tcp_client_max_idle = 0')
    assert f.contains('enable_krb5 = no')
    assert f.contains('krb5_principal = auditd')
    assert f.contains('distribute_network = no')


def test_audit_default_rules(host):
    f = host.file('/etc/audit/rules.d/audit.rules')

    assert not f.exists


@pytest.mark.parametrize("name", [
    ("10-base-config.rules"),
    ("21-no32bit.rules"),
    ("20-dont-audit.rules"),
    ("30-pci-dss-v31.rules"),
    ("30-ospp.rules"),
    ("41-containers.rules"),
    ("42-injection.rules"),
    ("43-module-load.rules"),
    ("99-finalize.rules")
])
def test_audit_rules_configuration_files(host, name):
    f = host.file('/etc/audit/rules.d/' + name)

    assert f.exists
    assert f.is_file
    assert f.mode == 0o640
    assert f.user == 'root'
    assert f.group == 'root'


def test_audisp_configuration_file(host):
    f = host.file('/etc/audisp/audisp.conf')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o640
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('q_depth = 250')
    assert f.contains('overflow_action = SYSLOG')
    assert f.contains('priority_boost = 4')
    assert f.contains('max_restarts = 10')
    assert f.contains('name_format = HOSTNAME')


@pytest.mark.parametrize("name", [
    ("af_unix"),
    ("sedispatch"),
    ("syslog")
])
def test_audisp_plugins_configuration_files(host, name):
    f = host.file('/etc/audisp/plugins.d/' + name + '.conf')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o640
    assert f.user == 'root'
    assert f.group == 'root'


def test_audisp_remote_configuration_file(host):
    f = host.file('/etc/audisp/audisp-remote.conf')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o640
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('remote_server =')
    assert f.contains('enable_krb5 =')


# def test_auditd_service(host):
#     s = host.service('auditd')
#
#     assert s.is_enabled


# def test_cron_aide(host):
#     f = host.file('/etc/cron.daily/auditd')
#
#     assert f.exists
#     assert f.is_file
#     assert f.mode == 0o750
#     assert f.user == 'root'
#     assert f.group == 'root'
#     assert f.contains('/sbin/service auditd rotate')
