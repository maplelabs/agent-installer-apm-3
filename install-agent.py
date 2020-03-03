"""
*******************
*Copyright 2017, MapleLabs, All Rights Reserved.
*
********************
"""

#!/usr/bin/env python

import argparse
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import zipfile
import json
from time import sleep


COLLCTD_SOURCE_URL = "https://github.com/maplelabs/collectd/releases/download/" \
                     "collectd-custom-5.6.2/collectd-custom-5.6.2.tar.bz2"
COLLCTD_SOURCE_FILE = "collectd-custom-5.6.2"

CONFIGURATOR_SOURCE_REPO = "https://github.com/maplelabs/configurator-exporter-apm-3"
CONFIGURATOR_DIR = "/opt/sfapm/configurator-exporter/"

COLLECTD_PLUGINS_REPO = "https://github.com/maplelabs/collectd-plugins"
COLLECTD_PLUGINS_ZIP = "https://github.com/maplelabs/collectd-plugins/archive/master.zip"
CONFIGURATOR_ZIP = "https://github.com/maplelabs/configurator-exporter-apm-3/archive/master.zip"
COLLECTD_PLUGINS_DIR = "/opt/sfapm/collectd/plugins"
COLLECTD_PLUGIN_MAPPING_FILE = "/opt/sfapm/configurator-exporter/config_handler/mapping/metrics_plugins_mapping.yaml"
FLUENTD_PLUGIN_MAPPING_FILE = "/opt/sfapm/configurator-exporter/config_handler/mapping/logging_plugins_mapping.yaml"
COLLECTD_CENTOS7_X86_64 = "https://github.com/maplelabs/collectd/releases/download/collectd-centos-7-1.0.2/collectd-centos-7.tar.bz2"
COLLECTD_RHEL7_X86_64 = "https://github.com/maplelabs/collectd/releases/download/collectd-rhel-7-1.0.36/collectd-rhel-7.tar.bz2"
COLLECTD_UBUNTU18_X86_64 = "https://github.com/maplelabs/collectd/releases/download/collectd-ubuntu-18-1.0.6/collectd-ubuntu-18.tar.bz2"
COLLECTD_UBUNTU16_X86_64 = "https://github.com/maplelabs/collectd/releases/download/collectd-ubuntu-16-1.0.2/collectd-ubuntu-16.tar.bz2"
FLUENTD_RHEL16_X86_64 = "https://github.com/snappyflow/omnibus-td-agent/releases/download/td-agent-rhel-7.1.0.2/td-agent-rhel7.tar.gz"
FLUENTD_UBUNTU18_X86_64 = "https://github.com/snappyflow/omnibus-td-agent/releases/download/td-agent-ubuntu-18.1.0.3/td-agent-ubuntu18.tar.gz"
FLUENTD_UBUNTU16_X86_64 = "https://github.com/snappyflow/omnibus-td-agent/releases/download/td-agent-ubuntu-16.1.0.3/td-agent-ubuntu16.tar.gz"
FLUENTD_CENTOS7_X86_64 = "https://github.com/snappyflow/omnibus-td-agent/releases/download/td-agent-centos-7.1.0.38/td-agent-centos7.tar.gz"

DEFAULT_RETRIES = 3

DEFAULT_CONFIGURATOR_PORT = 8585

# check output function for python 2.6
if "check_output" not in dir(subprocess):
    def f(*popenargs, **kwargs):
        if 'stdout' in kwargs:
            raise ValueError('stdout argument not allowed, it will be overridden.')
        process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
        output, unused_err = process.communicate()
        retcode = process.poll()
        if retcode:
            cmd = kwargs.get("args")
            if cmd is None:
                cmd = popenargs[0]
            raise subprocess.CalledProcessError(retcode, cmd)
        return output


    subprocess.check_output = f


def set_env(**kwargs):
    for key, value in kwargs.iteritems():
        os.environ[key] = value


def kill_process(pid):
    if pid:
        print "Kill process ID {0}".format(pid)
        try:
            os.kill(int(pid), signal.SIGKILL)
        except:
            print "Failed to kill the process with pid {0}".format(pid)


def run_call(cmd, shell):
    """
    run a command don't check output
    :param cmd:
    :param shell:
    :return:
    """
    try:
        subprocess.call(cmd, shell=shell)
    except subprocess.CalledProcessError as error:
        print >> sys.stderr, "Error: {0}".format(error)
        print "error ignored"
        return


def download_file(url, local_path, proxy=None):
    if proxy:
        cmd = "wget -e use_proxy=on -e http_proxy={0} -O {1} {2}".format(proxy, local_path, url)
    else:
        cmd = "wget -O {0} {1}".format(local_path, url)
    print cmd
    run_call(cmd, shell=True)


def download_and_extract_tar(tarfile_url, local_file_name, tarfile_type=None, extract_dir=None, proxy=None):
    if extract_dir is None:
        extract_dir = '/tmp'
    if tarfile_type is None:
        tarfile_type = "r:gz"

    download_file(tarfile_url, local_file_name, proxy)

    print "untar " + local_file_name
    try:
        tar = tarfile.open(local_file_name, tarfile_type)
        tar.extractall(extract_dir)
        tar.close()
    except tarfile.TarError as err:
        print >> sys.stderr, err


def unzip_file(zip_file, target_dir="/tmp"):
    zip_ref = zipfile.ZipFile(zip_file, 'r')
    zip_ref.extractall(target_dir)
    zip_ref.close()


def clone_git_repo(REPO_URL, LOCAL_DIR, proxy=None):
    if proxy:
        cmd = "git config --global http.proxy {0}".format(proxy)
        run_call(cmd, shell=True)
    command = "git clone {0} {1}".format(REPO_URL, LOCAL_DIR)
    print command
    run_call(command, shell=True)


def update_hostfile():
    hosts_file = "/etc/hosts"
    hostname = platform.node()
    hostname = hostname.strip()
    ips = subprocess.check_output(['hostname', '--all-ip-addresses'])
    IP = ips.strip()
    try:
        f = open(hosts_file, "r")
        data = f.readlines()
        new_data = []
        found = False
        for line in data:
            if hostname in line and not line.startswith(IP):
                new_data.append(line)
                found = True
            elif IP in line and not line.startswith("#"):
                if hostname not in line:
                    line = "{0} {1}".format(line, hostname)
                    new_data.append(line)
                else:
                    new_data.append(line)
                found = True
            else:
                new_data.append(line)
        if not found:
            hostname = hostname + '\n'
            line = "{0} {1}".format(IP, hostname)
            new_data.append(line)
        f.close()

        f = open(hosts_file, 'w')
        f.write(''.join(new_data))
        f.close()
    except:
        print "FAILED to update hostname"


def check_open_port_available(port, address="127.0.0.1"):
    # Create a TCP socket
    port = int(port)
    s = socket.socket()
    print "Attempting to connect to %s on port %s" % (address, port)
    try:
        s.connect((address, port))
        print "Port {0} already in use".format(port)
        return False
    except socket.error, e:
        print "Port {0} is available".format(port)
        return True


def modify_plugin_input(plugin_input):
    import yaml
    with open(COLLECTD_PLUGIN_MAPPING_FILE, "r") as inp:
        plugin_input_file = inp.read()
    metrics_mapping = yaml.load(plugin_input_file)
    try:
        for service in plugin_input.keys():
            if "agentConfig" in plugin_input[service] and plugin_input[service]["agentConfig"]:
                agent_plugin = plugin_input[service]['agentConfig']
                for item in agent_plugin.keys():
                    if item == "interval":
                        metrics_mapping[service][0][item] = int(agent_plugin["interval"])
                    for service_item in metrics_mapping[service][0]["config"]:
                        if service_item["fieldName"] == item:
                            service_item["defaultValue"] = agent_plugin[item]
    except Exception as err:
        print "Exception in modify_plugin_input due to {0}".format(str(err))
        return
    mapping_yaml_out = yaml.dump(yaml.load(json.dumps(metrics_mapping)), default_flow_style=False)
    with open(COLLECTD_PLUGIN_MAPPING_FILE, "w") as out:
        out.write(mapping_yaml_out)


def modify_logger_input(plugin_input):
    import yaml
    with open(FLUENTD_PLUGIN_MAPPING_FILE, "r") as inp:
        plugin_input_file = inp.read()
    metrics_mapping = yaml.load(plugin_input_file)
    try:
        for service in plugin_input.keys():
            if "loggerConfig" in plugin_input[service] and plugin_input[service]["loggerConfig"]:
                for logger_plugin in plugin_input[service]["loggerConfig"]:
                    if logger_plugin["name"] in metrics_mapping:
                        plugin_name = logger_plugin["name"]
                        for item in metrics_mapping[plugin_name]['source']:
                            for input_item in logger_plugin:
                                if item == input_item:
                                    metrics_mapping[plugin_name]['source'][item] = logger_plugin[item]
    except Exception as err:
        print "Exception in modify_logger_input due to {0}".format(str(err))
        return
    mapping_yaml_out = yaml.dump(yaml.load(json.dumps(metrics_mapping)), default_flow_style=False)
    with open(FLUENTD_PLUGIN_MAPPING_FILE, "w") as out:
        out.write(mapping_yaml_out)


class DeployAgent:
    def __init__(self, host, port, proxy=None, retries=None ,update = False):
        self.host = host
        self.port = port
        self.proxy = proxy
        self.retries = retries
        self.update = update
        if self.retries is None:
            self.retries = DEFAULT_RETRIES
        self.os = get_os()
        self.version = get_os_version()
        self.python = '/opt/sfapm/sfapm-venv/bin/python'
        self.pip = self.python + " -m pip"
        if os.path.isfile("/usr/bin/python"):
            self.python_def_env = "/usr/bin/python"
        else:
            self.python_def_env = "python"
        self.pip_def_env = self.python_def_env + " -m pip"
            
    def _run_cmd(self, cmd, shell, ignore_err=False, print_output=False):
        """
        return output and status after runing a shell command
        :param cmd:
        :param shell:
        :param ignore_err:
        :param print_output:
        :return:
        """
        print cmd
        for i in xrange(self.retries):
            try:
                output = subprocess.check_output(cmd, shell=shell)
                if print_output:
                    print output
                    return output
                return
            except subprocess.CalledProcessError as error:
                if not ignore_err:
                    print >> sys.stderr, "ERROR: {0}".format(error)
                    sleep(0.05)
                    continue
                else:
                    print >> sys.stdout, "WARNING: {0}".format(error)
                    return
        sys.exit(1)

    def get_required_pippack_to_be_inst(self ,py_requirements):
        output = self._run_cmd(self.pip+" freeze", shell=True, ignore_err=True, print_output= True)
        installed_packages_list = output.splitlines()
        pip_pckgs = ''
        if os.path.isfile(py_requirements):
            with open(py_requirements,"r") as fp:
                pckg_tb_ins = fp.read().splitlines()
            pckg_tb_ins = set(pckg_tb_ins)
            installed_packages_list = set(installed_packages_list)
            for item in pckg_tb_ins.difference(installed_packages_list):
                pip_pckgs = pip_pckgs + item +' '
        return pip_pckgs
    def _add_proxy_for_curl_in_file(self, proxy, file_name):
        cmd = 'sed -i "s|curl|curl -x {0}|g" {1}'.format(proxy, file_name)
        print cmd
        self._run_cmd(cmd, shell=True, ignore_err=True)

    def _add_proxy_for_rpm_in_file(self, proxy, file_name):
        proxy_url = str(proxy).replace('http://', '')
        proxy_url = str(proxy_url).replace('https://', '')
        proxy_url = proxy_url.split(':')
        if len(proxy_url) > 1:
            result = ''.join([i for i in proxy_url[1] if i.isdigit()])
            cmd = 'sed -i "s|rpm|rpm --httpproxy {0} --httpport {1}|g" {2}'.format(proxy_url[0],
                                                                                   result, file_name)
            print cmd
            self._run_cmd(cmd, shell=True, ignore_err=True)

    def install_dev_tools(self):
        """
        install development tools and dependencies required to compile collectd
        :return:
        """
        if self.os == "ubuntu" or self.os == "debian":
            print "found ubuntu installing development tools and dependencies..."
            cmd1 = "DEBIAN_FRONTEND='noninteractive' apt-get -y -o Dpkg::Options::='--force-confdef' " \
                   "-o Dpkg::Options::='--force-confold' update"
            cmd2 = "DEBIAN_FRONTEND='noninteractive' apt-get -y -o Dpkg::Options::='--force-confdef' " \
                   "-o Dpkg::Options::='--force-confold' install gcc make libssl-dev libffi-dev curl python-dev sudo wget " \
                   "libmysqlclient-dev libcurl4-openssl-dev sysstat krb5-user libkrb5-dev"
            cmd3 = ""
            if self.version == "18.04":
                cmd3 = "DEBIAN_FRONTEND='noninteractive' apt-get -y install libcurl3 "
            self._run_cmd(cmd1, shell=True)
            self._run_cmd(cmd2, shell=True)
            if cmd3:
                self._run_cmd(cmd3, shell=True)

        elif self.os == "centos" or self.os == "redhat":
            print "found centos/redhat installing developments tools and dependencies..."
            cmd1 = "yum install --skip-broken -y gcc gcc-c++ redhat-lsb-core rpm-build curl python-devel sudo mysql-devel wget bzip2 perfi sysstat nc krb5-devel"
            self._run_cmd(cmd1, shell=True)

    def create_virtual_env(self):
        print "Creating Virtual Env sfapm-venv"
        if self.proxy:
            cmd2 = "{0} install virtualenv --proxy {1}".format(self.pip_def_env, self.proxy)
        else:
            cmd2 = "{0} install virtualenv".format(self.pip_def_env)
        self._run_cmd(cmd2, shell=True)
        create_venv = "{0} -m virtualenv /opt/sfapm/sfapm-venv/".format(self.python_def_env)
        self._run_cmd(create_venv, shell=True)
        print "Downgrading pip to 9.0.2 in virtual env"
        if self.proxy:
            cmd2 = "{0} install pip==9.0.2 --proxy {1}".format(self.pip, self.proxy)
        else:
            cmd2 = "{0} install pip==9.0.2".format(self.pip)
        self._run_cmd(cmd2, shell=True)

    def install_pip(self):
        print "install latest version of pip"
        pip_install_url = "https://bootstrap.pypa.io/2.6/get-pip.py"
        local_file = "/tmp/get-pip.py"
        download_file(pip_install_url, local_file, self.proxy)
        self._run_cmd("{0} {1} {2}".format(self.python_def_env, local_file, "pip==9.0.2"), shell=True)
    def install_pyyaml(self):
        print "Installing PyYaml to default python environment for satisfying installer script dependency"
        if self.proxy:
            cmd2 = "{0} install pyyaml --proxy {1}".format(self.pip_def_env, self.proxy)
        else:
            cmd2 = "{0} install pyyaml".format(self.pip_def_env)
        self._run_cmd(cmd2, shell=True)

    def install_python_packages(self):
        """
        install required python packages
        :return:
        """
        print "install python packages using pip"
        if self.proxy:
            cmd2 = "{0} install --upgrade setuptools collectd psutil argparse pyyaml requests " \
                   "mako web.py pyopenssl --proxy {1}".format(self.pip, self.proxy)
        else:
            cmd2 = "{0} install --upgrade setuptools collectd psutil argparse pyyaml mako " \
                   "requests web.py pyopenssl".format(self.pip)
        self._run_cmd(cmd2, shell=True)

    def setup_collectd(self):
        """
        install a custoum collectd from source
        :return:
        """
        # download and extract collectd
        try:
            shutil.rmtree("/opt/sfapm/collectd", ignore_errors=True)
        except shutil.Error:
            pass
        print "downloading collectd..."
        #if platform.machine() == "x86_64":

        if self.os == "centos":
            if self.version >="7.0":
                download_and_extract_tar(tarfile_url=COLLECTD_CENTOS7_X86_64, local_file_name="/tmp/collectd-prebuilt.tar",
                                     proxy=self.proxy, extract_dir="/opt/sfapm", tarfile_type="r:bz2")
        if self.os == "ubuntu":
            if self.version.startswith("16"):
                download_and_extract_tar(tarfile_url=COLLECTD_UBUNTU16_X86_64, local_file_name="/tmp/collectd-prebuilt.tar",
                                     proxy=self.proxy, extract_dir="/opt/sfapm", tarfile_type="r:bz2")
            elif self.version.startswith("18"):
                download_and_extract_tar(tarfile_url=COLLECTD_UBUNTU18_X86_64, local_file_name="/tmp/collectd-prebuilt.tar",
                                     proxy=self.proxy, extract_dir="/opt/sfapm", tarfile_type="r:bz2")
            else:
                #To be tested with other ubuntu versions
                download_and_extract_tar(tarfile_url=COLLECTD_UBUNTU16_X86_64, local_file_name="/tmp/collectd-prebuilt.tar",
                                     proxy=self.proxy, extract_dir="/opt/sfapm", tarfile_type="r:bz2")
        if self.os == "debian":
            #To be tested with debian flavor machines other than ubuntu
            download_and_extract_tar(tarfile_url=COLLECTD_UBUNTU16_X86_64, local_file_name="/tmp/collectd-prebuilt.tar",
                                     proxy=self.proxy, extract_dir="/opt/sfapm", tarfile_type="r:bz2")

        if self.os == "redhat":
            if self.version >="7.0":
                download_and_extract_tar(tarfile_url=COLLECTD_RHEL7_X86_64, local_file_name="/tmp/collectd-prebuilt.tar",
                                     proxy=self.proxy, extract_dir="/opt/sfapm", tarfile_type="r:bz2")

    def create_collectd_service(self):
        """
        create a service for collectd installed
        :return:
        """
        if self.os == "ubuntu" or self.os == "debian":
            print "found ubuntu ..."
            print "ubuntu version: {0}".format(self.version)
            if self.version < "16.04":
                try:
                    shutil.copyfile("/opt/sfapm/collectd/init_scripts/ubuntu14.init",
                                    "/etc/init.d/collectd")
                except shutil.Error as err:
                    print >> sys.stderr, err
                self._run_cmd("chmod +x /etc/init.d/collectd", shell=True)
            else:
                try:
                    shutil.copyfile("/opt/sfapm/collectd/init_scripts/ubuntu16.init",
                                    "/etc/systemd/system/collectd.service")
                    if os.path.isfile("/opt/sfapm/collectd/init_scripts/collectd_default") and not os.path.isfile(
                            "/etc/default/collectd"):
                        shutil.copyfile("/opt/sfapm/collectd/init_scripts/collectd_default",
                                        "/etc/default/collectd")
                except shutil.Error as err:
                    print >> sys.stderr, err
                self._run_cmd("systemctl daemon-reload", shell=True, ignore_err=True)
                self._run_cmd("systemctl enable collectd", shell=True, ignore_err=True)
        elif self.os == "centos" or self.os == "redhat":
            print "found centos ..."
            print "centos version: {0}".format(self.version)
            if self.version < "7.0":
                try:
                    shutil.copyfile("/opt/sfapm/collectd/init_scripts/centos6.init",
                                    "/etc/init.d/collectd")
                except shutil.Error as err:
                    print >> sys.stderr, err
                self._run_cmd("chmod +x /etc/init.d/collectd", shell=True)
            else:
                try:
                    shutil.copyfile("/opt/sfapm/collectd/init_scripts/centos7.init",
                                    "/etc/systemd/system/collectd.service")
                    if os.path.isfile("/opt/sfapm/collectd/init_scripts/collectd_default") and not os.path.isfile(
                            "/etc/default/collectd"):
                        shutil.copyfile("/opt/sfapm/collectd/init_scripts/collectd_default",
                                        "/etc/default/collectd")
                except shutil.Error as err:
                    print >> sys.stderr, err
                self._run_cmd("systemctl daemon-reload", shell=True, ignore_err=True)
                self._run_cmd("systemctl enable collectd", shell=True, ignore_err=True)

        print "terminate any old instance of collectd if available"
        self._run_cmd("kill $(ps aux | grep -v grep | grep 'collectd' | awk '{print $2}')", shell=True, ignore_err=True)

    def start_collectd_service(self):
        print "start collectd ..."
        if self.os in ["ubuntu","debian", "centos", "redhat"]:
            self._run_cmd("service collectd start", shell=True, print_output=True)
            sleep(5)
            self._run_cmd("service collectd status", shell=True, print_output=True)
        else:
            bin_file = "/opt/sfapm/collectd/sbin/collectd"
            config_file = "/opt/sfapm/collectd/etc/collectd.conf"
            pid_file = "/opt/sfapm/collectd/var/run/collectd.pid"
            cmd = "nohup {0} -C {1} -P {2} &> /dev/null &".format(bin_file, config_file, pid_file)
            print cmd
            run_call(cmd, shell=True)
    def start_collectd(self):
        print "terminate any old instance of collectd if available"
        self._run_cmd("kill $(ps aux | grep -v grep | grep 'collectd' | awk '{print $2}')", shell=True, ignore_err=True)
        bin_file = "/opt/sfapm/collectd/sbin/collectd"
        config_file = "/opt/sfapm/collectd/etc/collectd.conf"
        cmd = "{0} -C {1}".format(bin_file, config_file)
        print cmd
        run_call(cmd, shell=True)
        sleep(1)
        pid = self._get_collectd_pid()
        if not pid:
            run_call(cmd, shell=True)
            sleep(1)

    def install_fluentd(self):
        """
        install fluentd and start the service
        :return:
        """

        print "Removing fluentd if exists"
        if self.os == "ubuntu" or self.os == "debian":
            if self.os == "ubuntu":
                if self.version.startswith("16"):
                    download_and_extract_tar(tarfile_url=FLUENTD_UBUNTU16_X86_64, local_file_name="/tmp/fluentd-prebuilt.tar",
                                     proxy=self.proxy, extract_dir="/opt/sfapm/", tarfile_type="r:")
                elif self.version.startswith("18"):
                    download_and_extract_tar(tarfile_url=FLUENTD_UBUNTU18_X86_64, local_file_name="/tmp/fluentd-prebuilt.tar",
                                     proxy=self.proxy, extract_dir="/opt/sfapm/", tarfile_type="r:")
                else:
                    #To be tested with other versions of Ubuntu
                    download_and_extract_tar(tarfile_url=FLUENTD_UBUNTU16_X86_64, local_file_name="/tmp/fluentd-prebuilt.tar",
                                     proxy=self.proxy, extract_dir="/opt/sfapm/", tarfile_type="r:")
            else:
                #To be tested with  Debian Flavors other than ubuntu
                download_and_extract_tar(tarfile_url=FLUENTD_UBUNTU16_X86_64, local_file_name="/tmp/fluentd-prebuilt.tar",
                                     proxy=self.proxy, extract_dir="/opt/sfapm/", tarfile_type="r:")
            self._run_cmd("sudo apt install -y build-essential", shell=True)
            self._run_cmd("sudo apt install -y automake autoconf libtool", shell=True)
            self._run_cmd("sudo apt install -y libgeoip-dev", shell=True)
            cmd = "sudo dpkg -i /opt/sfapm/td-agent/td-agent_3.5.1-0_amd64.deb"
            self._run_cmd(cmd, ignore_err=True, shell=True)
        if self.os in ["centos", "redhat"]:
            print "Removing fluentd if exists"
            self._run_cmd("sudo yum remove -y td-agent*", shell =True)
            print "install fluentd for centos/redhat {0} {1}".format(self.os,self.version)
            try:
                shutil.rmtree("/opt/sfapm/td-agent", ignore_errors=True)
            except shutil.Error:
                pass
            if self.os == "centos":
                if self.version >= "7.0":
                    download_and_extract_tar(tarfile_url=FLUENTD_CENTOS7_X86_64, local_file_name="/tmp/fluentd-prebuilt.tar",
                                     proxy=self.proxy, extract_dir="/opt/sfapm/", tarfile_type="r:")
            if self.os == "redhat":
                if self.version >= "7.0":
                    download_and_extract_tar(tarfile_url=FLUENTD_RHEL16_X86_64, local_file_name="/tmp/fluentd-prebuilt.tar",
                                     proxy=self.proxy, extract_dir="/opt/sfapm/", tarfile_type="r:")
            self._run_cmd('sudo yum groupinstall -y "Development Tools"', shell=True)
            self._run_cmd("sudo yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm", shell=True, ignore_err=True)
            self._run_cmd("sudo yum install -y https://rpmfind.net/linux/centos/7.7.1908/os/x86_64/Packages/GeoIP-devel-1.5.0-14.el7.x86_64.rpm", shell=True, ignore_err=True)
            cmd = "sudo rpm -i /opt/sfapm/td-agent/td-agent-3.5.1-0.el7.x86_64.rpm"
            self._run_cmd(cmd, ignore_err=True, shell=True)
        """
        self._run_cmd("yes | cp ./td-agent.conf /opt/td-agent/etc/td-agent/", shell=True)
        self._run_cmd("yes | cp ./td-agent.conf /etc/td-agent/", shell=True)
        """
        self._run_cmd("sed -i '/port 8888/s/^/#/' /opt/sfapm/td-agent/td-agent/etc/td-agent/td-agent.conf", shell=True)
        self._run_cmd("sed -i '/port 8888/s/^/#/' /opt/sfapm/td-agent/etc/td-agent/td-agent.conf", shell=True)
        cmd = "usermod -a -G adm td-agent"
        print "Adding user td-agent to the group adm"
        self._run_cmd(cmd, ignore_err=True, shell=True)
        cmd = "chmod 777 /etc/init.d/td-agent"
        self._run_cmd(cmd, ignore_err=True, shell=True)
        print "Install fluentd gems..."
        print "Install fluentd fluent-plugin-elasticsearch..."
        self._run_cmd("/usr/sbin/td-agent-gem install fluent-plugin-elasticsearch", shell=True)
        print "Install fluentd fluent-plugin-multi-format-parser..."
        self._run_cmd("/usr/sbin/td-agent-gem install fluent-plugin-multi-format-parser", shell=True)
        print "Install fluentd fluentd-plugin-geoip..."
        self._run_cmd("/usr/sbin/td-agent-gem install fluent-plugin-geoip", shell=True)
   
    def start_fluentd_service(self):
        print "start fluentd ..."

        self._run_cmd("/etc/init.d/td-agent start", shell=True)
        sleep(5)
        print "Get fluentd status..."
        self._run_cmd("/etc/init.d/td-agent status", shell=True, print_output=True)
        self._run_cmd("systemctl enable td-agent", shell=True, ignore_err=True)

    def add_collectd_plugins(self):
        """
        add plugins to collectd installed
        :return:
        """
        download_file(COLLECTD_PLUGINS_ZIP, local_path="/tmp/collectd-plugins.zip", proxy=self.proxy)
        unzip_file("/tmp/collectd-plugins.zip")
        if os.path.exists("/opt/sfapm/collectd/plugins"):
            shutil.rmtree("/opt/sfapm/collectd/plugins")
        try:
            shutil.copytree("/tmp/collectd-plugins-master", "/opt/sfapm/collectd/plugins")
        except shutil.Error as err:
            print >> sys.stderr, err
        #Changed data dir to use base path /opt/sfapm/collectd
        self._run_cmd("sed -i 's/\/opt\/collectd\/var\/lib/\/opt\/sfapm\/collectd\/var\/lib/g' /opt/sfapm/collectd/plugins/constants.py", shell=True, ignore_err=True)
        self._run_cmd("sed -i 's/\/opt\/collectd/\/opt\/sfapm\/collectd/g' /opt/sfapm/collectd/plugins/libjolokia.py",shell=True, ignore_err=True)
        self._run_cmd("sed -i 's/\/opt\/collectd/\/opt\/sfapm\/collectd/g' /opt/sfapm/collectd/plugins/libtomcatjolokia.py",shell=True, ignore_err=True)
        py_requirements = "{0}/requirements.txt".format(COLLECTD_PLUGINS_DIR)
        pip_pckgs = self.get_required_pippack_to_be_inst(py_requirements)
        if pip_pckgs:
            if self.proxy:
                cmd = "{0} install {1} --proxy {2}".format(self.pip, pip_pckgs, self.proxy)
            else:
                cmd = "{0} install {1}".format(self.pip, pip_pckgs)
            self._run_cmd(cmd, shell=True, ignore_err=True)

    def _check_configurator_status(self, port=DEFAULT_CONFIGURATOR_PORT):
        try:
            import urllib2
            url = "http://127.0.0.1:%s" % (port)
            proxy_handler = urllib2.ProxyHandler({})
            opener = urllib2.build_opener(proxy_handler)
            req = urllib2.Request(url)
            resp = opener.open(req)
            return resp.code
        except Exception:
            return 404

    def verify_configurator(self):
        print "verify configurator"
        code = self._check_configurator_status(self.port)
        count = 0
        while code != 200:
            if count == 6:
                print >> sys.stderr, "Error: Configurator-exporter not running"
                sys.exit(128)
            count += 1
            sleep(5)
            code = self._check_configurator_status(self.port)
        print "verified"

    def _get_configurator_pid(self):
        pid = self._run_cmd("ps -face | grep -v grep | grep 'api_server' | awk '{print $2}'",
                            shell=True, print_output=True)
        return pid

    def _get_collectd_pid(self):
        pid = self._run_cmd("ps -face | grep -v grep | grep 'collectd' | awk '{print $2}'",
                            shell=True, print_output=True)
        return pid

    def stop_configurator_process(self):
        print "Stopping configurator"
        kill_process(self._get_configurator_pid())

    def install_configurator(self):
        """
        install and start configurator
        :return:
        """
        # kill existing configurator service

        self.stop_configurator_process()
        # sleep(0.5)
        if os.path.isdir(CONFIGURATOR_DIR):
            shutil.rmtree(CONFIGURATOR_DIR, ignore_errors=True)
        print "downloading configurator..."
        download_file(CONFIGURATOR_ZIP, local_path="/tmp/configurator.zip", proxy=self.proxy)
        unzip_file("/tmp/configurator.zip")
        try:
            shutil.copytree("/tmp/configurator-exporter-apm-3-master", "/opt/sfapm/configurator-exporter/")
        except shutil.Error as err:
            print >> sys.stderr, err

        print "Downloading GeoIP database..."
        try:
            self._run_cmd("rm -rf /usr/share/GeoLite2-City*", shell=True)
            self._run_cmd("mv /opt/sfapm/configurator-exporter/GeoLite2-City /usr/share/GeoLite2-City", ignore_err=True,
                          shell=True)

        except Exception as err:
            print "Failed to download GeoIP database : {0}".format(str(err))

        print "setup configurator..."
        if not self.update:
            if os.path.isfile("{0}requirements.txt".format(CONFIGURATOR_DIR)):
                if self.proxy:
                    cmd = "{0} install -r {1}requirements.txt --proxy {2}".format(self.pip, CONFIGURATOR_DIR, self.proxy)
                else:
                    cmd = "{0} install -r {1}requirements.txt".format(self.pip, CONFIGURATOR_DIR)
                self._run_cmd(cmd, shell=True, ignore_err=True)

            if os.path.isdir(CONFIGURATOR_DIR):
                print "starting configurator ..."
                self.create_configurator_service()

    def create_configurator_service(self):
        """
        create a service for collectd installed
        :return:
        """
        print "create_configurator_Service started"
        print "OS is: {0}".format(self.os)
        if self.os == "ubuntu" or self.os == "debian":
            print "found ubuntu ..."
            print "ubuntu version: {0}".format(self.version)
            if self.version < "16.04":
                try:
                    shutil.copyfile("/opt/sfapm/configurator-exporter/init_scripts/configurator.conf",
                                    "/etc/init/configurator.conf")
                except shutil.Error as err:
                    print >> sys.stderr, err
            else:
                try:
                    shutil.copyfile("/opt/sfapm/configurator-exporter/init_scripts/configurator.service",
                                    "/etc/systemd/system/configurator.service")
                except shutil.Error as err:
                    print >> sys.stderr, err
                self._run_cmd("systemctl daemon-reload", shell=True, ignore_err=True)
                self._run_cmd("systemctl enable configurator", shell=True, ignore_err=True)

        elif self.os == "centos" or self.os == "redhat":
            print "found centos ..."
            print "centos version: {0}".format(self.version)
            if self.version < "7.0":
                try:
                    shutil.copyfile("/opt/sfapm/configurator-exporter/init_scripts/configurator_centos6",
                                    "/etc/init.d/configurator")
                except shutil.Error as err:
                    print >> sys.stderr, err
                self._run_cmd("chmod +x /etc/init.d/configurator", shell=True)
            else:
                try:
                    shutil.copyfile("/opt/sfapm/configurator-exporter/init_scripts/configurator.service",
                                    "/etc/systemd/system/configurator.service")
                except shutil.Error as err:
                    print >> sys.stderr, err
                self._run_cmd("systemctl daemon-reload", shell=True, ignore_err=True)
                self._run_cmd("systemctl enable configurator", shell=True, ignore_err=True)

        print "terminate any old instance of configurator if available"
        self._run_cmd("kill $(ps aux | grep -v grep | grep 'api_server' | awk '{print $2}')", shell=True,
                      ignore_err=True)

    def restart_configurator_service(self):
        print "restart configurator ..."
        self._run_cmd("service configurator restart", shell=True, print_output=True)
        sleep(5)
        self._run_cmd("service configurator status", shell=True, print_output=True)

    def start_configurator_service(self):
        print "start configurator ..."
        self._run_cmd("service configurator start", shell=True, print_output=True)
        sleep(5)
        self._run_cmd("service configurator status", shell=True, print_output=True)

        self.verify_configurator()

    def remove_iptables_rule(self):
        """
        clear any previously added iptable rule on port_number
        :param port_number:
        :return:
        """
        clean_rule = "iptables -D INPUT -p tcp -m tcp --dport {0} -j ACCEPT".format(self.port)
        self._run_cmd(clean_rule, shell=True, ignore_err=True)

    def configure_iptables(self):
        """
        add rule to accept traffic on configurator port
        :param port_number
        :return:
        """
        add_rule = "iptables -I INPUT 1 -p tcp -m tcp --dport {0} -j ACCEPT".format(self.port)
        save_rule = "iptables-save"
        if self.os == "ubuntu" or self.os == "debian":
            restart_iptables = "service ufw restart"
        elif self.os in ["centos", "redhat"]:
            save_rule = "iptables-save | sudo tee /etc/sysconfig/iptables"
            restart_iptables = "service iptables restart"
        else:
            restart_iptables = "service iptables restart"

        self.remove_iptables_rule()
        self._run_cmd(add_rule, shell=True, ignore_err=True)
        self._run_cmd(save_rule, shell=True, ignore_err=True)
        self._run_cmd(restart_iptables, shell=True, ignore_err=True)


def install(collectd=True, setup=True, fluentd=True, configurator=True, configurator_host="0.0.0.0",
            configurator_port=DEFAULT_CONFIGURATOR_PORT,
            http_proxy=None, https_proxy=None, retries=None, plugin_input=None,update = False):
    """
    use this function to controll installation process
    :param collectd:
    :param fluentd:
    :param configurator:
    :param configurator_host:
    :param configurator_port:
    :param http_proxy:
    :param https_proxy:
    :return:
    """

    import time
    begin = time.time()
    if http_proxy and not os.environ.get("http_proxy"):
        set_env(http_proxy=http_proxy)
    if https_proxy and not os.environ.get("https_proxy"):
        set_env(http_proxy=https_proxy)

    proxy = https_proxy
    if not proxy:
        proxy = http_proxy

    obj = DeployAgent(host=configurator_host, port=configurator_port, retries=retries ,update = update)
    if update:
        if os.path.exists("/tmp/collectd-plugins-conf"):
            shutil.rmtree("/tmp/collectd-plugins-conf")
        if os.path.exists("/tmp/collectd-conf"):
            shutil.rmtree("/tmp/collectd-conf")
        if os.path.exists("/tmp/configurator-prev-config-data"):
            shutil.rmtree("/tmp/configurator-prev-config-data")
        shutil.copytree("/opt/sfapm/collectd/conf/","/tmp/collectd-plugins-conf")
        shutil.copytree("/opt/sfapm/collectd/etc", "/tmp/collectd-conf")
        shutil.copytree("/opt/sfapm/configurator-exporter/config_handler/data", "/tmp/configurator-prev-config-data")
        print "Stopping Configurator ,collectd, fluentd"
        obj.stop_configurator_process()
        obj._run_cmd("service collectd stop", shell=True, print_output=True)
        obj._run_cmd("service td-agent stop", shell=True, print_output=True)
    if setup:
        start = time.time()
        update_hostfile()
        obj.install_dev_tools()
        obj.install_pip()
        obj.install_pyyaml()
        if not os.path.exists("/opt/sfapm/sfapm-venv/") and not update:
            obj.create_virtual_env()
        obj.install_python_packages()
        print "=================package setup time in seconds============"
        print time.time() - start
        print "===================================="

    if collectd:
        start = time.time()
        print "Started installing collectd ..."
        obj.setup_collectd()
        obj.add_collectd_plugins()
        if not update:
            obj.create_collectd_service()
        print "=================collectd setup time in seconds============"
        print time.time() - start
        print "===================================="

    if fluentd and not update:
        start = time.time()
        print "started installing fluentd ..."
        obj.install_fluentd()
        print "=================fluentd setup time in seconds============"
        print time.time() - start
        print "===================================="

    if configurator:
        start = time.time()
        obj.stop_configurator_process()
        print "started installing configurator ..."
        obj.install_configurator()
        if not update:
            obj.configure_iptables()
        print "=================configurator setup time in seconds============"
        print time.time() - start
        print "===================================="
    if update:
        print "Restoring previous Collectd  and Configurator Config"
        if os.path.exists("/opt/sfapm/collectd/conf/"):
            shutil.rmtree("/opt/sfapm/collectd/conf/")
        if os.path.exists("/opt/sfapm/collectd/etc/"):
            shutil.rmtree("/opt/sfapm/collectd/etc/")
        if os.path.exists("/opt/sfapm/configurator-exporter/config_handler/data"):
            shutil.rmtree("/opt/sfapm/configurator-exporter/config_handler/data")
        shutil.copytree("/tmp/collectd-plugins-conf","/opt/sfapm/collectd/conf/")
        shutil.copytree("/tmp/collectd-conf", "/opt/sfapm/collectd/etc")
        shutil.copytree("/tmp/configurator-prev-config-data", "/opt/sfapm/configurator-exporter/config_handler/data")
    print "=================starting all the services========"
    print "===================================="
    if collectd:
        obj.start_collectd_service()
        obj.restart_configurator_service()
    if fluentd:
        obj.start_fluentd_service()
    if configurator:
        obj.start_configurator_service()
    modify_plugin_input(plugin_input)
    modify_logger_input(plugin_input)
    print "=================total time in seconds============"
    print time.time() - begin
    print "===================================="
    sys.exit(0)


def get_os():
    """
    return os name
    :return:
    """
    os = platform.dist()[0].lower()
    if os == "oracle":
        return "redhat"
    else:
        return os

def get_os_version():
    """
    return os version
    :return:
    """
    if len(platform.dist()[1].split(".")) == 2:
        version = platform.dist()[1]
    else:
        version = ".".join(platform.dist()[1].split(".")[0:2])
    return version

if __name__ == '__main__':
    """main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-ss', '--skipsetup', action='store_false', default=True, dest='initialsetup',
                        help='skip collectd installation')
    parser.add_argument('-sc', '--skipcollectd', action='store_false', default=True, dest='installcollectd',
                        help='skip collectd installation')
    parser.add_argument('-sf', '--skipfluentd', action='store_false', default=True, dest='installfluentd',
                        help='skip fluentd installation')
    parser.add_argument('-sce', '--skipconfigurator', action='store_false', default=True, dest='installconfigurator',
                        help='skip configurator installation')
    parser.add_argument('-p', '--port', action='store', default="{0}".format(DEFAULT_CONFIGURATOR_PORT), dest='port',
                        help='port on which configurator will listen')
    parser.add_argument('-ip', '--host', action='store', default="0.0.0.0", dest='host',
                        help='host ip on which configurator will listen')
    parser.add_argument('--http_proxy', action='store', default="", dest='http_proxy',
                        help='http proxy for connecting to internet')
    parser.add_argument('--https_proxy', action='store', default="", dest='https_proxy',
                        help='https proxy for connecting to internet')
    parser.add_argument('--retries', type=int, dest='retries',
                        help='Retries on failure')
    parser.add_argument('-pi', '--plugin_input', action='store', default={}, dest='plugin_input', type=json.loads,
                        help='customised plugin input  details')
    parser.add_argument('-u', '--update', action='store_true', default=False, dest='update_agents',help='Updating agents with restored version of previous configs')
    args = parser.parse_args()
    if args.update_agents:
        print "Updating Agents"
        args.initialsetup = False
    install(collectd=args.installcollectd,
            setup=args.initialsetup,
            fluentd=args.installfluentd,
            configurator=args.installconfigurator,
            configurator_host=args.host,
            configurator_port=args.port,
            http_proxy=args.http_proxy,
            https_proxy=args.https_proxy,
            retries=args.retries,
            plugin_input= args.plugin_input,
            update = args.update_agents )
