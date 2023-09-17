import re
import json
import yaml
from sys import exit
from datetime import datetime as dt
from dateutil import tz
from netmiko import ConnectHandler, ConnLogOnly, file_transfer

class NetworkDevice:
    
    def __init__(self, cloud="", org_id="", key_file=r"/home/ecsupport/ecsupport-keypair.pem", ip_address="127.0.0.1", username='zsroot', port=22, filepath=r"/home/zsroot/"):
        #self.device_type = "auto-detect"
        self.ip_address = ip_address
        self.username = username
        #self.password = password
        self.port = port
        self.cloud = cloud
        self.org_id = org_id
        self.port = port
        self.key_file = key_file
        self.connection = self.connect()
        self.filepath = filepath        
        self.ec_dir = r"/sc/instances/edgeconnector0/"
        self.ec_dir_bin = rf"{self.ec_dir}bin"

        self.config_counters = ["smsvpnc_ec_comm_err_config_apply_fail",
                    "smsvpnc_ec_comm_err_config_apply_fail",
                    "smsvpnc_ec_comm_warn",
                    "sme_company_err_lookup_failed",
                    "sme_company_conf_err",
                    "ofw_err_when_no_conf",
                    "smconfig_err"
                    ]

        self.gateway_counters = ["smsvpnc_ec_tot_gateway_config_removed",
                    "smsvpnc_ec_tot_gateway_config_added", 
                    "smsvpnc_ec_err",
                    "smsvpnc_zengw_err",
                    "smsvpnc_gw_err"
                   ]

        self.pac_dns_counters = ["smsvpnc_gw_cur_pac_resolve_pending",
            "smsvpnc_gw_warn_pac_resolve_ip_zero",
            "smsvpnc_gw_cur_dns_resolve_pending",
            "smsvpnc_gw_err_pac",
            "smsvpnc_gw_tot_pac_resolve_failed",
            "smsvpnc_gw_err_dns",
            "smsvpnc_ziagw_err_pac"
            ]
        
        self.rule_err_counters = ["ofw_err_cfg"]
               
        self.mts_counters = ["smsvpnc_zengw_tot_mtsclt_conn_closed",
                    "smsvpnc_zengw_tot_mtsclt_conn_closed_reason",
                    "smsvpnc_zengw_tot_mtsclt_server_connected",
                    "smmts_err_clt_conn_open_failed",
                    "smmts_err_clt_conn_init_timedout",
                    "smmts_cur_master_ip"
                ]

        self.msb_counters = ["smsvpcn_ec_err_msb_dropped",
                "smsvpnc_ec_err_msb_dropped_tunnel_stale"
               ]
        
        self.svpn_tun_counters = ["smsvpnc_ctl_err",
                "smsvpnc_tunnel_err",
                "smsvpnc_data_err",
                "smsvpnc_ec_warn_gw_dtls2tls",
                "smsvpnc_ec_err_msb_dropped",
                "smsvpnc_ec_err_tunnel",
                "smsvpnc_mon_err_http_res_not_200_ok ",
                "smsvpnc_mon_err_http_req_send",
                "smsvpnc_mon_tot_tun_marked_deactivate"
               ]
        
        self.zpa_counters = ["smzpac_err",
            "smzpac_cur",
            "smzpac_tot",
            "ofw_err_zpa"
            ]
 
        self.cmd_dict = {"a": {
                            "a": r"/smmgr -s smedge=showgw",
                            "b": r"/smmgr -s smedge=showgw_full",
                            "c": r"/smmgr -s smedge=showgw_stats",
                            "d": r"/smmgr -s smedge=showtun",
                            "e": r"/smmgr -s smedge=showtun_full",
                            "f": r"/smmgr -s smedge=showtun_stats",
                            "g": rf"/smmgr -ys ofw='policy :cid {self.org_id}'",
                            "h": r"/smmgr -s show=companies"
                            },
                    "b": {
                            "a": rf"/smmgr -s cid={self.org_id} -ys show=znf_broker_info",
                            "b": rf"/smmgr -s verbose=yes -s cid={self.org_id} -ys show=zpac_app_info",
                            "c": rf"/smmgr -s ofw='appseg show more :cid {self.org_id}'",
                            "d": r"/smmgr -s show=dnsm_pool",
                            "e": r"/smmgr -s show=dnsm_map",
                            "f": r"/smmgr -s show=dnsm_pending"
                            },
                    "c": {
                            "a": r"/smmgr -s smedge=showctx",
                            "b": r"/smmgr -s ofw='session show more'",
                            "c": r"/smmgr -ys ofw=fqdn",
                            "d": rf"/smmgr -s ofw='policy :id {self.org_id} :type rdr :fmt raw'"
                            },
                    "d": r"/smmgr -k cfg_system_id -d stats",
                    "e": r"sudo januscli status | grep -i fingerprint"        
        }

    def connect(self):

        cc = {
            "device_type": "autodetect",
            "host": self.ip_address,
            "username": self.username,
            "use_keys": True,
            "key_file": self.key_file,
            "port": self.port
        }
        
        conn = ConnLogOnly(**cc)

        if conn is None:
            exit("Unable to establish SSH Session!!")
        else:
            return conn

    def disconnect(self):
        self.connection.disconnect()

    def send_command(self, command, timeout=10, fsm=True, prompt=r'#|\$|\>'):
        output = self.connection.send_command(command, read_timeout=timeout, use_textfsm=fsm, expect_string=prompt)
        return output

    def send_config_commands(self, commands):
        output = self.connection.send_config_set(commands)
        return output

    def __interactive_channel(self, command):

        prompt = self.connection.find_prompt()
        output = ""
        self.connection.write_channel(command)
        self.connection.write_channel("\n")

        while True:
            output += self.connection.read_channel()
            if prompt in output:
                return output
                break

    def __dict_sort(self, output):

        output_keys = list(output.keys())
        output_keys.sort()
        sorted_dict = {i: output[i] for i in output_keys}
        return sorted_dict

    def __print_output(self, output):
        
        if isinstance(output, dict):

            sorted_dict = self.__dict_sort(output)
            print(f'''\n
-----------------------------------------------------------------------------------
''')
            for k,v in sorted_dict.items():
                print(rf'| {k} : {v}')

            print(f'''\n
-----------------------------------------------------------------------------------
''')

        else:
            print(f'''\n
-----------------------------------------------------------------------------------
{output}
-----------------------------------------------------------------------------------
''')

    def __collect_user_debug_input(self, fw_debug=True):

        i = 0
        filter_ip = ""
        file_size = ""
        fwdebug_cip = ""
        
        while i < 3:
            user_input = input('''Please specify the file size.
-- Default value is 100MB.
-- Valid Values: 10G, 1G, 100M, 10M
-- If no change is required, please enter "No" or "no".
''').strip()
            if user_input == "No" or user_input == "no":
                file_size = "100M"
                break
            elif re.match(r"^(\d{1,4}[m,M,g,G])$", user_input):
                file_size = user_input
                break
            else:
                print("Please enter a valid value.")
                i += 1
                if i >= 3:
                    exit()
        return file_size

    def __verify_interface(self):
        """
        Private Method:  will test output of ifconfig <interface> command to ensure it is valid.
        """

        command = "ifconfig -l"
        output = cc1.send_command(command, timeout=15, fsm=True)
        interfaces = output.split(" ")

        i = 0
        while i < 3:
            try:
                user_input = input("Please provide the interface to take capture: ").strip()
            except ValueError:
                print(f"Please enter a valid value from the following list: {interfaces}")
                 
            if user_input in interfaces:
                return user_input
            else:
                print(f"Please enter a valid interface. \nFollowing is the list of valid interfaces: {interfaces}")
                i += 1
        exit()

    def __tcpdump_filters(self):

        i = 0

        while i < 3:
            user_input = input('''If you need to use any filters with Tcpdump, please provide them.
-- For example, 
-- If you want to capture for a specific IP, provide input as: host 10.1.1.1
-- If you want to capture for a specific port, provide input as: port 443
-- If you want to use other complex filters, provide input as: port 443 and tcp and host 10.1.1.1
-- If you do not want to specify any filter, please enter "No".
''').strip()
            if user_input in ["No", "N", "n", "no", "nO"]:
                return False
            elif re.match(r"^.+$", user_input):
                return user_input
            else:
                print("Please provide a valid value.")
                i += 1
        exit()

    def __tcpdump_packet_count(self):

        i = 0

        while i < 3:
            user_input = input('''Please provide the capture size.
-- Default value is set to 1000 packets. 
-- TCPDUMP will stop after capturing 1000 packets.
-- If you do not want to specify any custom value, please enter "No".
''').strip()
            if re.search(r"^\d+$", user_input):
                return int(user_input)
            elif user_input in ["No", "N", "n", "no", "nO"]:
                return False
            else:
                print("Please provide a valid value.")
                i += 1
        exit()

    def __validate_custom_input(self):
    
        """
        Function will validate the custom counters provided by the user for option "e"
    
        """
        valid_counters = []
        i = 0 

        while i < 3:
            user_input = input('''Please provide upto 5 SMSTAT counters:
-- -g option will be used for these counters.
-- Counter names should be strings containing only alphanumeric characters or "_" underscore.
-- Provide coma seperated values.
-- For example, smsvpnc_gw_err_gwc_moved, smsvpnc_ec_err_tunnel_no, smsvpcn_ec_err, smsvpnc_ctl_cur, smsvpnc_data_err_ .
''')
            counters = user_input.split(",")
            counters = [i.strip() for i in counters]

            if len(counters) > 5:
                print("Script Can Except only 5 custom SMSTAT counters..")
                i += 1
    
            else:
                for i in counters:
                    if re.search(r"^[a-zA-Z0-9_]+$", i):
                        valid_counters.append(i)
                    else:
                        print(f"Counter {i} is not valid..\n")
                        i += 1
            
            return valid_counters
    
    def __validate_date_time(self):
    
        """
        Function will validate the Start date/time and End date/time provided by user. 
    
        """
        
        i = 0
        format_string = "%d%b%Y:%H:%M:%S"

        while i < 3:
            start_time = input('''Please enter Start time in following format:
-- If start time is June 31, 2023 at 04:40:00 PM, please enter the following value: 31Jun2023:16:40:00
-- Another example: 11May2023:01:00:59
''')

            end_time = input('''Please enter End time in following format:
-- If start time is June 31, 2023 at 04:40:00 PM, please enter the following value: 31Jun2023:16:40:00
-- Another example: 11May2023:01:00:59
''')

            try: 
                s_time = dt.strptime(start_time, format_string)
                e_time = dt.strptime(end_time, format_string)
            except ValueError: 
                print(f"\n\n+++ Start or End time format is incorrect...+++\n+++ Supported format is: 01Mar2023:23:59:29 +++\n")
                exit("Try again!!")

            if s_time:
                if e_time:
                    if e_time > s_time:
                        stime = s_time.strftime(format_string)
                        etime = e_time.strftime(format_string)
                        return stime, etime
                    else:
                        print("End Time provided is earlier than the Start time value.")
                        i += 1
                else: 
                    print("Ivalid value provided for End Time.")
                    i += 1
            else:
                print("Ivalid value provided for End Time.")
                i += 1
    
    def __validate_interval(self):
    
        """
        Function will check the value provided as the "Interval"
    
        """

        i = 0

        while i < 3:
            user_input = input('''Please provide the interval in seconds, hours or days. 
Following are valid values:
-- For 10 second interval, use value: 10
-- For 1 hour interval, use value: 1h
-- For 1 day interval, use value: 1d
Note: Default interval will be 1 second and if you do not supply any value, 1 second interval will be used.
''')
            if user_input:
                if re.match(r"(^\d{1,4}$)|(^\d{1,2}h$)|(^\d{1,2}d$)", user_input):
                    return user_input
                else:
                    print("\n\n+++ Invalid 'Interval' value specified...+++\n")
                    i += 3
            else:
                return 1
        exit()

    def __validate_mode(self):

        i = 0 
        modes = ["diff", "difs", "stats"]

        while i < 3:
            user_input = input('''Please provide the mode for SMSTAT capture.
Valid modes are:
    1) diff/difs 
    2) stats
''')
            user_input = user_input.lower()
            if user_input in modes:
                return user_input
            else:
                print(f"{user_input} value provided is not valid.")
                i += 1
        exit()

    def collect_pcap(self):
        """
        Method will act as a wrapper around TCPDUMP to collect network packet captures on both Service and/or Management Interface
        """
        #self.interface = self.__verify_interface()
        self.filters = self.__tcpdump_filters()
        self.packet_count = self.__tcpdump_packet_count()
        n_time = dt.now(tz=tz.UTC).strftime("%Y-%m-%d-%H:%M:%S:%f")
        self.pcap_filename = f"{self.filepath}capture_{n_time}.pcap"

        if self.filters == False:
            
            command = f"sudo ZSINSTANCE={self.ec_dir} {self.ec_dir_bin}/smtcpdump.sh -s0 -w {self.pcap_filename} -c {self.packet_count} -i tap20 --smnet_intf nm"
            
            self.__print_output(command)
            
        else:
            
            command = f"sudo ZSINSTANCE={self.ec_dir} {self.ec_dir_bin}/smtcpdump.sh -s0 -w {self.pcap_filename} -c {self.packet_count} -i tap20 --smnet_intf nm -n {self.filters}"
            self.__print_output(command)

    def collect_smstat(self, option=""):

        """
        Method will collect SMSTAT counters for the specified time. 
        """

        stime, etime = self.__validate_date_time()
        interval=self.__validate_interval()
        mode = self.__validate_mode()
        n_time = dt.now(tz=tz.UTC).strftime("%Y-%m-%d-%H:%M:%S:%f")

        if option == "a":  # Option "a" will check for MTS Flaps

            self.mts_counters_file = f"{self.filepath}mts_counters_{n_time}.txt"
            counters_str = ' -g '.join([str(i.strip()) for i in self.mts_counters])
            command = rf'sudo {self.ec_dir_bin}/smstat -ys idir={self.ec_dir}log/statslog -ys stime={stime} -ys etime={etime} -ys interval={interval} -g {counters_str} -d {mode} > {self.mts_counters_file}'
            output = self.send_command(command, timeout=300, fsm=False)
            self.__print_output(output)

        elif option == "b": # Option "b" will check for Tunnel Flaps
            
            self.svpn_counters_file = f"{self.filepath}svpn_tun_counters_{n_time}.txt"
            counters_str = ' -g '.join([str(i.strip()) for i in self.svpn_tun_counters])
            command = rf'sudo {self.ec_dir_bin}/smstat -ys idir={self.ec_dir}log/statslog -ys stime={stime} -ys etime={etime} -ys interval={interval} -g {counters_str} -d {mode} > {self.svpn_counters_file}'
            output = self.send_command(command, timeout=300, fsm=False)
            self.__print_output(output)

        elif option == "c":  # Option "c" will check for ZPA Counters

            self.zpa_counters_file = f"{self.filepath}zpa_counters_{n_time}.txt"
            counters_str = ' -g '.join([str(i.strip()) for i in self.zpa_counters])
            command = rf'sudo {self.ec_dir_bin}/smstat -ys idir={self.ec_dir}log/statslog -ys stime={stime} -ys etime={etime} -ys interval={interval} -g {counters_str} -d {mode} > {self.zpa_counters_file}'
            return self.send_command(command, timeout=300, fsm=False)
            self.__print_output(output)

        elif option == "d":  # Option "d" will check for the MSB errors to find dropped sessions 
            
            self.msb_counters_file = f"{self.filepath}msb_counters_{n_time}.txt"
            counters_str = ' -g '.join([str(i.strip()) for i in self.msb_counters])
            command = rf'sudo {self.ec_dir_bin}/smstat -ys idir={self.ec_dir}log/statslog -ys stime={stime} -ys etime={etime} -ys interval={interval} -g {counters_str} -d {mode} > {self.msb_counters_file}'
            output = self.send_command(command, timeout=120, fsm=False)
            self.__print_output(output)

        elif option == "e":  # Option "e" will check for the PAC & DNS errors 
            
            self.pac_dns_counters_file = f"{self.filepath}pac_dns_counters_{n_time}.txt"
            counters_str = ' -g '.join([str(i.strip()) for i in self.pac_dns_counters])
            command = rf'sudo {self.ec_dir_bin}/smstat -ys idir={self.ec_dir}log/statslog -ys stime={stime} -ys etime={etime} -ys interval={interval} -g {counters_str} -d {mode} > {self.pac_dns_counters_file}'
            output = self.send_command(command, timeout=120, fsm=False)
            self.__print_output(output)

        elif option == "f":  # Option "f" will check for the gateway_counters errors
            
            self.gateway_counters_file = f"{self.filepath}gateway_counters_{n_time}.txt"
            counters_str = ' -g '.join([str(i.strip()) for i in self.gateway_counters])
            command = rf'sudo {self.ec_dir_bin}/smstat -ys idir={self.ec_dir}log/statslog -ys stime={stime} -ys etime={etime} -ys interval={interval} -g {counters_str} -d {mode} > {self.gateway_counters_file}'
            output = self.send_command(command, timeout=120, fsm=False)
            self.__print_output(output)

        elif option == "g":  # Option "g" will check for the config_counters errors to find dropped sessions 
            
            self.config_counters_file = f"{self.filepath}config_counters_{n_time}.txt"
            counters_str = ' -g '.join([str(i.strip()) for i in self.config_counters])
            command = rf'sudo {self.ec_dir_bin}/smstat -ys idir={self.ec_dir}log/statslog -ys stime={stime} -ys etime={etime} -ys interval={interval} -g {counters_str} -d {mode} > {self.config_counters_file}'
            output = self.send_command(command, timeout=120, fsm=False)
            self.__print_output(output)
        
        elif option == "h":  # Option "h" will check for the rule_err_counters errors to find dropped sessions 
            
            self.tf_rule_counters_file = f"{self.filepath}tf_rule_counters_{n_time}.txt"
            counters_str = ' -g '.join([str(i.strip()) for i in self.rule_err_counters])
            command = rf'sudo {self.ec_dir_bin}/smstat -ys idir={self.ec_dir}log/statslog -ys stime={stime} -ys etime={etime} -ys interval={interval} -g {counters_str} -d {mode} > {self.tf_rule_counters_file}'
            output = self.send_command(command, timeout=120, fsm=True)
            self.__print_output(output)

        elif option == "i":  # Option "i" will let use share the custom smstat counters 

            self.custom_counters_file = f"{self.filepath}custom_counters_{n_time}.txt"
            counters = self.__validate_custom_input()
            counters_str = ' -g '.join([str(i.strip()) for i in counters])
            command = rf'sudo {self.ec_dir_bin}/smstat -ys idir={self.ec_dir}log/statslog -ys stime={stime} -ys etime={etime} -ys interval={interval} -g {counters_str} -d {mode} > {self.custom_counters_file}'
            output = self.send_command(command, timeout=120, fsm=True)
            self.__print_output(output)

    def collect_logs(self):

        command = r"sudo arkecli backup --no-upload --paths"
        output = self.send_command(command, timeout=60, fsm=True)
        self.__print_output(output)
        return output

    def collect_web_debug(self,debug_flags="0xffffffff"):
        """
        Method will collect Debugs from the Cloud Connectors
        """
        
        n_time = dt.now(tz=tz.UTC).strftime("%Y-%m-%d-%H:%M:%S:%f")
        
        file_size = self.__collect_user_debug_input(fw_debug=False)
        
#        if filter_ip:
        self.debug_filename = f"{self.filepath}web-debug_{n_time}.log"
        command = f'sudo {self.ec_dir_bin}/smmgr -s debugflags={debug_flags} -s debugfilename={self.debug_filename} -s debuglogsize={file_size} -s debug=start'
        debug_output = self.send_command(command, timeout=30, fsm=True)
        self.__print_output(debug_output)
        return debug_output

    def collect_firewall_debug(self, debug_flags="0xffffffff", fw_flags="0xffffffff"):
        """
        Method will collect Firewall Debug logs
        """

        n_time = dt.now(tz=tz.UTC).strftime("%Y-%m-%d-%H:%M:%S:%f")
        file_size = self.__collect_user_debug_input(fw_debug=True)

        #if fw_cip:
        self.fwdebug_filename = f"{self.filepath}fw-debug_{n_time}.g"
        command = f'sudo {self.ec_dir_bin}/smmgr -s debugflags={debug_flags} -s fwdebug_flags={fw_flags} -s debugfilename={self.fwdebug_filename} -s debuglogsize={file_size} -s debug=start'
        fw_debug_output = self.send_command(command, timeout=30, fsm=True)
        self.__print_output(fw_debug_output)
        return fw_debug_output

    def stop_debug(self):
        command = f"sudo {self.ec_dir_bin}/smmgr -s debug=stop"
        stop_debug_output = self.send_command(command, timeout=30, fsm=True)
        self.__print_output(stop_debug_output)
 
    def execute_cmds(self, main_menu_option="", sub_menu_option=None):
 
        if sub_menu_option == None:

            if main_menu_option in ("e", "E"):

                cmd_string = self.cmd_dict[main_menu_option.lower()]
                command = rf"{cmd_string}"
                output = self.send_command(command, timeout=15, fsm=True)
                self.__print_output(output)
                return output
            
            else:
                cmd_string = self.cmd_dict[main_menu_option.lower()]
                command = rf"sudo {self.ec_dir_bin}{cmd_string}"
                output = self.send_command(command, timeout=15, fsm=True)
                self.__print_output(output)
                return output

        else:

            cmd_string = self.cmd_dict[main_menu_option.lower()][sub_menu_option.lower()]
            command = rf"sudo {self.ec_dir_bin}{cmd_string}"
            output = self.send_command(command, timeout=15, fsm=True)
            self.__print_output(output)
            return output

    def instance_details(self):
        '''
        Method will print the information about the CC Instance.
        '''
        command = "sudo januscli status"
        output = self.send_command(command, timeout=15, fsm=True)
        januscli_output = yaml.safe_load(output)
        out_dict = {}

        if isinstance(januscli_output, dict):

            for k,v in januscli_output.items():
                if k == "janus":
                    for i,j in v.items():
                        if i == "edge":
                            for key,value in j.items():
                                out_dict[rf'{value["name"].capitalize()}_ID'] = key
                                out_dict[rf'{value["name"].capitalize()}_probe_port'] = value["probe_port"]
                                out_dict[rf'{value["name"].capitalize()}_service_interface'] = value["service_interface"]
                                out_dict[rf'{value["name"].capitalize()}_version'] = value["version"]
                                out_dict[rf'{value["name"].capitalize()}_health_code'] = value["health_code"]
                                out_dict[rf'{value["name"].capitalize()}_directory'] = value["directory"]
                                out_dict[rf'{value["name"].capitalize()}_ZIA_VIP'] = value["zia_vip"]
                                out_dict[rf'{value["name"].capitalize()}_ZPA_Broker_IP'] = value["zpa_master_broker_ip"]
                                
                        elif i == "group":
                            for key,value in j.items():
                                out_dict["Group_Name"] = value["name"]
                                out_dict["Group_ID"] = key
                                out_dict["ZIA_ORG_ID"] = value["org_id"]
                                out_dict["Prov_URL"] = value["provisioning_url"]
                                out_dict["ZIA_Enabled"] = value["zia"]
                                out_dict["ZPA_Enabled"] = value["zpa"]
                                out_dict["ZIA_Cloud"] = value["zia_cloud"]
                                out_dict["Location_ID"] = value["location_id"]
                                out_dict["System_Fingerprint"] = value["system_fingerprint"]
                                out_dict["VM_ID"] = value["vm_id"]
                                out_dict["VM_Name"] = value["vm_name"]
                                
                        elif i == "loadbalancer":
                            for key,value in j.items():
                                out_dict[value["name"]+"_ID"] = key
                                out_dict[value["name"]+"_Role"] = value["role"]
                                out_dict[value["name"]+"_Directory"] = value["directory"]
                                out_dict[value["name"]+"_Service_Interface"] = value["service_interface"]
                                out_dict[value["name"]+"_Version"] = value["version"]
                                
                        elif i == "management_interface":
                            for key,value in j.items():
                                out_dict["MGMT_Name"] = key
                                out_dict["MGMT_IP"] = rf'{value["ip"]}/{value["netmask"]}'
                                out_dict["MGMT_NAT_IP"] = value["nat_ip"]
                                out_dict["MGMT_DNS"] = rf'{value["dns"]["nameservers"]}'
            
                        elif i == "netmap_service_interface":
                            for key,value in j.items():
                                out_dict[rf'SRVC_{value["unit_number"]}_Name'] = value["ip"]
                                out_dict[rf'SRVC_{value["unit_number"]}_IP'] = rf'{value["ip"]}/{value["netmask"]}'
                                out_dict[rf'SRVC_{value["unit_number"]}_DNS'] = rf'{value["dns"]["nameservers"]}'
                                out_dict[rf'SRVC_{value["unit_number"]}_SC_Name'] = value["sc_name"]
            
                        elif i == "package_upgrader":
                            for key,value in j.items():
                                if key == "janus updater":
                                    out_dict["Current_Janus_Version"] = value["current_package_version"]
            
            self.__print_output(out_dict)

        else:
            self.__print_output(output)
        
