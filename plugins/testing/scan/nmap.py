#!/usr/bin/env python
# -*- coding: utf-8 -*-

__license__ = """
GoLismero 2.0 - The web knife - Copyright (C) 2011-2014

Golismero project site: http://golismero-project.com
Golismero project mail: contact@golismero-project.com

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

from golismero.api.config import Config
from golismero.api.data.db import Database
from golismero.api.data.information.fingerprint import OSFingerprint, ServiceFingerprint
from golismero.api.data.information.portscan import Portscan
from golismero.api.data.information.traceroute import Traceroute, Hop
from golismero.api.data.resource.domain import Domain
from golismero.api.data.resource.ip import IP
from golismero.api.data.resource.mac import MAC
from golismero.api.data.vulnerability.infrastructure.vulnerable_service import VulnerableService
from golismero.api.data.vulnerability.malware.malicious import MaliciousIP
from golismero.api.external import run_external_tool, tempfile, find_binary_in_path
from golismero.api.logger import Logger
from golismero.api.net import ConnectionSlot
from golismero.api.plugin import ImportPlugin, TestingPlugin

import shlex

from socket import getservbyname
from time import time
from traceback import format_exc
from warnings import warn

try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET


#------------------------------------------------------------------------------
class NmapImportPlugin(ImportPlugin):


    #--------------------------------------------------------------------------
    def is_supported(self, input_file):
        if input_file and input_file.lower().endswith(".xml"):
            with open(input_file, "rU") as fd:
                return "<nmaprun " in fd.read(10240)
        return False


    #--------------------------------------------------------------------------
    def import_results(self, input_file):
        results = NmapScanPlugin.parse_nmap_results(None, input_file)
        if results:
            Database.async_add_many(results)
            Logger.log("Loaded %d elements from file: %s" %
                       (len(results), input_file))
        else:
            Logger.log_verbose("No data found in file: %s" % input_file)


#------------------------------------------------------------------------------
class NmapScanPlugin(TestingPlugin):

    # List of supported NSE scripts.
    # The plugin will attempt to find which ones exist in the locally
    # installed version of Nmap, and run only those.
    SCRIPTS = (
        "afp-path-vuln",
        "cvs-brute-repository",
        "dns-blacklist",
        "dns-random-srcport",
        "dns-random-txid",
        "dns-recursion",
        "dns-service-discovery",
        "dns-srv-enum",
        "dns-update",
        "dns-zeustracker",
        "domino-enum-users",
        "fcrdns",
        "finger",
        "ftp-anon",
        "ftp-bounce",
        "ftp-libopie",
        "ftp-proftpd-backdoor",
        "ftp-vsftpd-backdoor",
        "ftp-vuln-cve2010-4221",
        "hadoop-datanode-info",
        "hadoop-jobtracker-info",
        "hadoop-namenode-info",
        "hadoop-secondary-namenode-info",
        "hadoop-tasktracker-info",
        "http-adobe-coldfusion-apsa1301",
        "http-awstatstotals-exec",
        "http-axis2-dir-traversal",
        "http-barracuda-dir-traversal",
        "http-coldfusion-subzero",
        "http-drupal-enum-users",
        "http-frontpage-login",
        "http-git",
        #"http-google-malware", # requires API key
        "http-iis-short-name-brute",
        "http-iis-webdav-vuln",
        "http-litespeed-sourcecode-download",
        "http-majordomo2-dir-traversal",
        "http-malware-host",
        "http-method-tamper",
        "http-open-proxy",
        "http-phpmyadmin-dir-traversal",
        "http-slowloris-check",
        "http-userdir-enum",
        "http-vmware-path-vuln",
        "http-virustotal",
        "http-vuln-cve2006-3392",
        "http-vuln-cve2009-3960",
        "http-vuln-cve2010-0738",
        "http-vuln-cve2010-2861",
        "http-vuln-cve2011-3192",
        "http-vuln-cve2011-3368",
        "http-vuln-cve2012-1823",
        "http-vuln-cve2013-0156",
        "http-vuln-cve2013-7091",
        "http-vuln-cve2014-2128",
        "http-xssed",
        "http-wordpress-enum",
        "irc-unrealircd-backdoor",
        "jdwp-version",
        "maxdb-info",
        "ms-sql-dac",
        "ms-sql-empty-password",
        "mysql-empty-password",
        "mysql-enum",
        "mysql-vuln-cve2012-2122",
        "oracle-enum-users",
        "p2p-conficker",
        "qconn-exec",
        "quake1-info",
        "rdp-enum-encryption",
        "rdp-vuln-ms12-020",
        "realvnc-auth-bypass",
        "rmi-vuln-classloader",
        "samba-vuln-cve-2012-1182",
        "smb-vuln-ms10-061",
        "smtp-open-relay",
        "socks-open-proxy",
        "sshv1",
        "ssl-ccs-injection",
        "ssl-known-key",
        "sslv2",
        "stuxnet-detect",
        "teamspeak2-version",
        "tftp-enum",
        "vnc-info",
        "vuze-dht-info",
        "x11-access",
    )


    #--------------------------------------------------------------------------
    def check_params(self):
        if not find_binary_in_path("nmap"):
            raise RuntimeError(
                "Nmap not found! You can download it from: http://nmap.org/")


    #--------------------------------------------------------------------------
    def get_accepted_types(self):
        return [IP]


    #--------------------------------------------------------------------------
    def run(self, info):

        # Get the list of supported NSE scripts.
        # XXX FIXME this is very wrong!!! But for some reason
        # the RPC is not giving me back the KeyError exception
        # and just prints the traceback on the screen.
        if self.state.check("supported_nse_scripts"):
            supported_nse_scripts = self.state.get("supported_nse_scripts")
        else:
            supported_nse_scripts = []
            for script in self.SCRIPTS:
                code = run_external_tool(
                    "nmap", ["--script-help=%s.nse" % script],
                    callback=lambda x:x)
                if code == 0:
                    supported_nse_scripts.append(script)
            supported_nse_scripts = tuple(supported_nse_scripts)
            self.state.set("supported_nse_scripts", supported_nse_scripts)
        if not supported_nse_scripts:
            Logger.log_more_verbose(
                "Warning: no compatible NSE scripts found!")

        # Build the command line arguments for Nmap.
        args = shlex.split( Config.plugin_args["args"] )
        if info.version == 6 and "-6" not in args:
            args.append("-6")
        if supported_nse_scripts and "--script" not in args and not any(
                x.startswith("--script=") for x in args):
            args.append( "--script=" + ",".join(
                x + ".nse" for x in supported_nse_scripts) )
        args.append( info.address )

        # The Nmap output will be saved in XML format in a temporary file.
        with tempfile(suffix = ".xml") as output:
            args.append("-oX")
            args.append(output)

            # Run Nmap and capture the text output.
            Logger.log("Launching Nmap against: %s" % info.address)
            Logger.log_more_verbose("Nmap arguments: %s" % " ".join(args))
            with ConnectionSlot(info.address):
                t1 = time()
                code = run_external_tool("nmap", args,
                                         callback=Logger.log_verbose)
                t2 = time()

            # Log the output in extra verbose mode.
            if code:
                Logger.log_error(
                    "Nmap execution failed, status code: %d" % code)
                return
            Logger.log(
                "Nmap scan finished in %s seconds for target: %s"
                % (t2 - t1, info.address))

            # # DEBUG
            # with open(output, "rb") as fd1:
            #     with open("nmap_test.xml", "wb") as fd2:
            #         import shutil
            #         shutil.copyfileobj(fd1, fd2)
            # # DEBUG

            # Parse and return the results.
            return self.parse_nmap_results(info, output)


    #--------------------------------------------------------------------------
    @classmethod
    def parse_nmap_results(cls, info, output_filename):
        """
        Convert the output of an Nmap scan to the GoLismero data model.

        :param info: Data object to link all results to (optional).
        :type info: IP

        :param output_filename: Path to the output filename.
            The format should always be XML.
        :type output_filename:

        :returns: Results from the Nmap scan.
        :rtype: list(Data)
        """

        # Parse the scan results.
        # On error log the exception and continue.
        results = []
        hostmap = {}
        if info:
            hostmap[info.address] = info
        try:
            tree = ET.parse(output_filename)
            scan = tree.getroot()

            # Get the scan arguments and log them.
            try:
                args = scan.get("args", None)
                if not args:
                    args = scan.get("scanner", None)
                if args:
                    Logger.log_more_verbose(
                        "Loading data from scan: %s" % args)
            except Exception:
                ##raise # XXX DEBUG
                pass

            # For each scanned host...
            for host in scan.findall(".//host"):
                try:

                    # Parse the information from the scanned host.
                    results.extend( cls.parse_nmap_host(host, hostmap) )

                # On error, log the exception and continue.
                except Exception, e:
                    Logger.log_error_verbose(str(e))
                    Logger.log_error_more_verbose(format_exc())

        # On error, log the exception.
        except Exception, e:
            Logger.log_error_verbose(str(e))
            Logger.log_error_more_verbose(format_exc())

        # Return the results.
        return results


    #--------------------------------------------------------------------------
    @classmethod
    def parse_nmap_host(cls, host, hostmap):
        """
        Convert the output of an Nmap scan to the GoLismero data model.

        :param host: XML node with the scanned host information.
        :type host: xml.etree.ElementTree.Element

        :param hostmap: Dictionary that maps IP addresses to IP data objects.
            This prevents the plugin from reporting duplicated addresses.
            Updated by this method.
        :type hostmap: dict( str -> IP )

        :returns: Results from the Nmap scan for this host.
        :rtype: list(Data)
        """

        # File format details can be found here:
        # https://svn.nmap.org/nmap/docs/nmap.dtd

        # This is the object where we'll pin all the vulnerabilities.
        vuln_ip = None

        # Get the timestamp.
        timestamp = host.get("endtime")
        if timestamp:
            timestamp = long(timestamp)
        if not timestamp:
            timestamp = host.get("starttime")
            if timestamp:
                timestamp = long(timestamp)

        # Get all the IP addresses. Skip the MAC addresses.
        ip_addresses = []
        for node in host.findall(".//address"):
            if node.get("addrtype", "") not in ("ipv4, ipv6"):
                continue
            address = node.get("addr")
            if not address:
                continue
            if address not in hostmap:
                hostmap[address] = IP(address)
            ip_addresses.append( hostmap[address] )
            if vuln_ip is None:
                vuln_ip = hostmap[address]

        # Link all the IP addresses to each other.
        ips_visited = set()
        for ip_1 in ip_addresses:
            if ip_1.address not in ips_visited:
                ips_visited.add(ip_1.address)
                for ip_2 in ip_addresses:
                    if ip_2.address not in ips_visited:
                        ips_visited.add(ip_2.address)
                        ip_1.add_resource(ip_2)
        ips_visited.clear()

        # Get all the MAC addresses.
        mac_addresses = []
        seen_macs = set()
        for node in host.findall(".//address"):
            if node.get("addrtype", "") != "mac":
                continue
            address = node.get("addr")
            if not address:
                continue
            if address not in seen_macs:
                seen_macs.add(address)
            mac_addresses.append( MAC(address) )

        # Get all the hostnames.
        domain_names = []
        for node in host.findall(".//hostname"):
            hostname = node.get("name")
            if not hostname:
                continue
            if hostname not in hostmap:
                hostmap[hostname] = Domain(hostname)
            domain_names.append( hostmap[hostname] )

        # Link all domain names to all IP addresses.
        for name in domain_names:
            for ip in ip_addresses:
                name.add_resource(ip)

        # Link all MAC addresses to all IP addresses.
        for mac in mac_addresses:
            for ip in ip_addresses:
                mac.add_resource(ip)

        # Abort if no resources were found.
        if not ip_addresses and not domain_names and not mac_addresses:
            return []

        # Get the port scan results.
        ports = set()
        services = set()
        for node in host.findall(".//port"):
            try:
                portid   = node.get("portid")
                protocol = node.get("protocol")
                if protocol not in ("tcp", "udp"):
                    continue
                try:
                    port = int(portid)
                except Exception:
                    port = getservbyname(portid)
                state = node.find("state").get("state")
                if state not in ("open", "closed", "filtered"):
                    continue
                ports.add( (state, protocol, port) )
                if state == "open":
                    serv_node = node.find("service")
                    if serv_node is not None:
                        service = serv_node.get("name")
                        if service:
                            if service == "https":
                                service  = "http"
                                protocol = "SSL"
                            elif serv_node.get("tunnel") == "ssl":
                                protocol = "SSL"
                            else:
                                protocol = protocol.upper()
                            services.add( (service, port, protocol) )
            except Exception:
                warn("Error parsing port scan results: %s" % format_exc(),
                     RuntimeWarning)

        # Get the traceroute results.
        traces = []
        for node in host.findall(".//trace"):
            try:
                if node.get("port") is None or node.get("proto") is None:
                    # This happens for trivial cases like empty traceroute
                    # result tags. Example: trying to traceroute a host that's
                    # only one hop away from you, like your home router.
                    continue
                port   = int( node.get("port") )
                proto  = node.get("proto")
                hops   = {}
                broken = False
                for node in node.findall(".//hop"):
                    try:
                        ttl       = int( node.get("ttl") )
                        address   = node.get("ipaddr")
                        rtt       = float( node.get("rtt") )
                        hostname  = node.get("host", None)
                        hops[ttl] = Hop(address, rtt, hostname)
                    except Exception:
                        warn("Error parsing traceroute results: %s" %
                             format_exc(), RuntimeWarning)
                        broken = True
                        break
                if not broken:
                    if hops:
                        ttl = hops.keys()
                        sane_hops = tuple(
                            hops.get(i, None)
                            for i in xrange(min(*ttl), max(*ttl) + 1)
                        )
                    else:
                        sane_hops = ()
                    traces.append( (port, proto, sane_hops) )
            except Exception:
                warn("Error parsing traceroute results: %s" %
                     format_exc(), RuntimeWarning)

        # Get the fingerprint results.
        fingerprints = set()
        for node in host.findall(".//osmatch"):
            try:
                name = node.get("name", None)
                for node in node.findall(".//osclass"):
                    accuracy = float( node.get("accuracy") )
                    os_type = node.get("type", None)
                    vendor = node.get("vendor", None)
                    family = node.get("osfamily", None)
                    generation = node.get("osgen", None)
                    cpe = node.find("cpe").text
                    fingerprints.add( (
                        cpe, accuracy,
                        name, vendor, os_type, generation, family
                    ) )
            except Exception:
                warn("Error parsing OS fingerprint results: %s" % format_exc(),
                     RuntimeWarning)

        # This is where we'll gather all the results.
        results = ip_addresses + domain_names + mac_addresses

        # Link the port scan results to the IP addresses.
        for ip in ip_addresses:
            try:
                portscan = Portscan(ip, ports, timestamp)
            except Exception:
                warn(format_exc(), RuntimeWarning)
                continue
            results.append(portscan)

        # Link the service identification results to the IP addresses.
        for service, port, protocol in services:
            try:
                sfp = ServiceFingerprint(service, port, protocol)
            except Exception:
                warn(format_exc(), RuntimeWarning)
                continue
            for ip in ip_addresses:
                ip.add_information(sfp)
            results.append(sfp)

        # Link the traceroute results to the IP addresses.
        for ip in ip_addresses:
            if ip.version == 4:
                for trace in traces:
                    try:
                        traceroute = Traceroute(ip, *trace)
                    except Exception:
                        warn(format_exc(), RuntimeWarning)
                        continue
                    results.append(traceroute)

        # Link the fingerprint results to the IP addresses.
        for ip in ip_addresses:
            for args in fingerprints:
                try:
                    fingerprint = OSFingerprint(*args)
                except Exception:
                    warn(format_exc(), RuntimeWarning)
                    continue
                ip.add_information(fingerprint)
                results.append(fingerprint)

        # Parse the NSE script results.
        if vuln_ip is not None:
            for node in host.findall(".//hostscript"):
                for node in node.findall(".//script"):
                    try:
                        script = node.get("id")
                        output = node.get("output")
                        if "\r\n" in output:
                            output = output.replace("\r\n", "\n")
                        method = script.replace("-", "_").replace(".", "_")
                        method = "parse_" + method
                        if hasattr(cls, method):
                            r = getattr(cls, method)(
                                output, vuln_ip, host, hostmap)
                            if r:
                                results.extend(r)
                    except Exception:
                        warn("Error parsing NSE script results: %s" % \
                             format_exc(), RuntimeWarning)

        # Return the results.
        return results

    @classmethod
    def parse_afp_path_vuln(cls, output, vuln_ip, host, hostmap):
        """
        Parse the output of the afp-path-vuln NSE script.

        :param output: NSE script output.
        :type output: str

        :param vuln_ip: IP address to pin the vulnerabilities to.
        :type vuln_ip: IP

        :param host: XML node with the scanned host information.
        :type host: xml.etree.ElementTree.Element

        :param hostmap: Dictionary that maps IP addresses to IP data objects.
            This prevents the plugin from reporting duplicated addresses.
            Updated by this method.
        :type hostmap: dict( str -> IP )

        :returns: Results from the Nmap scan for this host.
        :rtype: list(Data)
        """
        # TODO get the real port number instead of the default
        # TODO extract the proper description string instead of appending.
        if "VULNERABLE:" in output:
            vuln = VulnerableService(vuln_ip, 548, "TCP")
            vuln.description += "\nNSE Script output:\n" + output
            return [vuln]

    @classmethod
    def parse_dns_blacklist(cls, output, vuln_ip, host, hostmap):
        """
        Parse the output of the dns-blacklist NSE script.

        :param output: NSE script output.
        :type output: str

        :param vuln_ip: IP address to pin the vulnerabilities to.
        :type vuln_ip: IP

        :param host: XML node with the scanned host information.
        :type host: xml.etree.ElementTree.Element

        :param hostmap: Dictionary that maps IP addresses to IP data objects.
            This prevents the plugin from reporting duplicated addresses.
            Updated by this method.
        :type hostmap: dict( str -> IP )

        :returns: Results from the Nmap scan for this host.
        :rtype: list(Data)
        """
        for line in output.split("\n"):
            if line.endswith(" - PROXY") or line.endswith(" - SPAM"):
                vuln = MaliciousIP(vuln_ip)
                vuln.description += "\nNSE Script output:\n" + output
                return [vuln]
