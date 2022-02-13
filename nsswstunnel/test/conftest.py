import pytest
import subprocess
import logging

import nss.nss as nss
import nss.ssl as ssl

@pytest.fixture(scope='session')
def server_name():
    return 'nsswstunnel.tdihp.github.com'


@pytest.fixture(scope='session')
def server_cert(tmp_path_factory, server_name):
    """returns cert and key paths"""
    path = tmp_path_factory.mktemp('openssl')
    key_path = str(path / 'server.key')
    cert_path = str(path / 'server.crt')
    openssl_args = [
        'openssl', 'req', '-batch',
        '-newkey', 'rsa:2048', '-nodes', '-keyout', key_path,
        '-x509', '-days', '1', '-out', cert_path,
        '-subj', '/CN=' + server_name, 
    ]
    subprocess.run(openssl_args, check=True)
    return cert_path, key_path


@pytest.fixture(scope='session')
def certdb(tmp_path_factory, server_cert, server_name):
    """generates cert db and return its path"""
    path = tmp_path_factory.mktemp('nsscertdb')
    certdb = 'sql:' + str(path)
    init_certdb_cmd = ['certutil', '-N', '--empty-password', '-d', certdb]
    subprocess.run(init_certdb_cmd, check=True)
    add_server_cert_cmd = [
        'certutil', '-A', '-t', 'C,,', '-d', certdb,
        '-n', server_name, '-i', server_cert[0]]
    subprocess.run(add_server_cert_cmd, check=True)
    return certdb


@pytest.fixture(scope='function', autouse=True)
def nssinit(certdb):
    nss.nss_init(certdb)
    ssl.set_domestic_policy()
    # yield
    # ssl.clear_session_cache()
    # nss.nss_shutdown()


@pytest.fixture(scope='function', autouse=True)
def loginit(caplog):
    caplog.set_level(logging.DEBUG, logger="nsswstunnel")

