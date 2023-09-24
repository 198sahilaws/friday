import re, os
from sys import exit
from datetime import datetime as dt

def pre_login_data():

    def cloud():

        name = {
            "1": "Zscaler.net",
            "2": "Zscloud.net",
            "3": "Zscalertwo.net",
            "4": "Zscalerthree.net",
            "5": "Zscalerbeta.net"
        }
        
        try:
            i = 0
            while i < 3:

                user_input = input('''Please select the Cloud: 
1) Zscaler.net
2) Zscloud.net
3) Zscalertwo.net
4) Zscalerthree.net
5) Zscalerbeta.net
''').strip()
                
                if re.match(r"^[1-5]$", user_input):
                    #user_input = int(user_input)
                    return name[user_input]
                else:
                    print(f"'{user_input}' is not a valid option..\n\n")
                    i += 1
            exit("Wrong Input provided. Script will now exit!!")

        except ValueError:
            print(f"'{user_input}' is not a valid Integer value..")
               
    def orgid():
        try:
            i = 0
            while i < 3:
                
                user_input = input("Please enter the ORG ID: ").strip()
                if re.match(r"^\d{5,10}$", user_input):
                    #user_input = int(user_input)
                    return user_input
                else:
                    print(f"'{user_input}' is not a valid ORG ID..\n\n")
                    i += 1
            exit("Wrong Input provided. Script will not exit!!")
            
        except ValueError:
            print(f"'{user_input}' is not a valid integer value..")        
            
    def verify_port():
        try:
            i = 0
            while i < 3:
                
                user_input = input("Please enter the CC/BC Port: ").strip()
                if re.match(r"^\d{1,5}$", user_input):
                    #user_input = int(user_input)
                    return user_input
                else:
                    print(f"'{user_input}' is not a valid port number..\n\n")
                    i += 1
            exit("Wrong Input provided. Script will not exit!!")
            
        except ValueError:
            print(f"'{user_input}' is not a valid integer value..")   
                    
    def connector_ip():
 
        i = 0
        while i < 3:

            user_input = input('Please enter the Cloud Connector IP Address: ').strip()
                
            if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", user_input):
                #user_input = int(user_input)
                return user_input
            else:
                print(f"'{user_input}' is not a valid option..\n\n")
                i += 1
        exit("Wrong Input provided. Script will now exit!!")

    def cc_ssh_key():
        i = 0
        while i < 3:

            user_input = input('Please provide the path+name for the private SSH key for logging into CC/BC: ').strip()
                
            if os.path.isfile(user_input):
                return user_input
            else:
                print(f"File: '{user_input}' does not exist..\n\n")
                i += 1
        exit("Wrong Input provided. Script will now exit!!")

    def check_ecsupport_jumpserver():
        '''
        Function will test if script is executed from ECSupport Jumpserver by Zscaler support or not.
        '''
        ecsupport_key = r"/home/ecsupport/ecsupport-keypair.pem"
        output_dict = {}

        if os.path.isfile(ecsupport_key):
            output_dict["cloud_name"] = cloud()
            output_dict["company"] = orgid()
            output_dict["ssh_port"] = verify_port()

            return output_dict

        else:
            output_dict["cloud_name"] = cloud()
            output_dict["company"] = orgid()
            output_dict["ssh_port"] = verify_port()
            output_dict["ec_ip"]= connector_ip()
            output_dict["ec_ssh_key"]= cc_ssh_key()

            return output_dict

    return check_ecsupport_jumpserver()

def print_menu(menu):
    for k,v in menu.items():
        print(f"{k}: {v}")

def validate_user_input(menu_name):

    if menu_name == "main_menu":

        try:
            i = 0
            while i < 3:
                user_input = input("Please select a valid option: ").strip()
                if re.match(r"^[0-5]$", user_input):
                    return user_input
                else:
                    print(f"'{user_input}' is not valid. Please enter a valid option..\n\n")
                    i += 1
            exit("Wrong Input provided. Script will not exit!!")

        except ValueError:
            print(f"'{user_input}' is not a valid Integer value..")
    
    elif menu_name == "debug_menu":

        try:
            i = 0 
            while i < 3:
                user_input = input("Please select a valid option: ").strip()
                if re.match(r"^[a,b,c,A,B,C,0]$", user_input):
                    return user_input
                else:
                    print(f"'{user_input}' is not valid. Please enter a valid option..\n\n")
                    i += 1
            exit("Wrong Input provided. Script will not exit!!")

        except ValueError:
            print(f"'{user_input}' is not a valid string value..")

    elif menu_name == "smstat_menu":
        
        try:
            i = 0 
            while i < 3:
                user_input = input("Please select a valid option: ").strip()
                if re.match(r"^[a,b,c,d,e,f,g,h,A,B,C,D,E,F,G,H,0]$", user_input):
                    return user_input
                else:
                    print(f"'{user_input}' is not valid. Please enter a valid option..\n\n")
                    i += 1
            exit("Wrong Input provided. Script will not exit!!")

        except ValueError:
            print(f"'{user_input}' is not a valid string value..")

    elif menu_name == "cmd_menu":

        try:
            i = 0 
            while i < 3:
                user_input = input("Please select a valid option: ").strip()
                if re.match(r"^[a,b,c,d,e,A,B,C,D,E,0]$", user_input):
                    return user_input
                else:
                    print(f"'{user_input}' is not valid. Please enter a valid option..\n\n")
                    i += 1
            exit("Wrong Input provided. Script will not exit!!")

        except ValueError:
            print(f"'{user_input}' is not a valid string value..")

    elif menu_name == "tunnel_gateway_cmd_menu":

        try:
            i = 0 
            while i < 3:
                user_input = input("Please select a valid option: ").strip()
                if re.match(r"^[a,b,c,d,e,f,g,h,i,A,B,C,D,E,F,G,H,I,0]$", user_input):
                    return user_input
                else:
                    print(f"'{user_input}' is not valid. Please enter a valid option..\n\n")
                    i += 1
            exit("Wrong Input provided. Script will not exit!!")

        except ValueError:
            print(f"'{user_input}' is not a valid string value..")

    elif menu_name == "zpa_cmd_menu":

        try:
            i = 0 
            while i < 3:
                user_input = input("Please select a valid option: ").strip()
                if re.match(r"^[a,b,c,d,e,f,g,A,B,C,D,E,F,G,0]$", user_input):
                    return user_input
                else:
                    print(f"'{user_input}' is not valid. Please enter a valid option..\n\n")
                    i += 1
            exit("Wrong Input provided. Script will not exit!!")

        except ValueError:
            print(f"'{user_input}' is not a valid string value..")

    elif menu_name == "session_cmd_menu":

        try:
            i = 0 
            while i < 3:
                user_input = input("Please select a valid option: ").strip()
                if re.match(r"^[a,b,c,d,A,B,C,D,0]$", user_input):
                    return user_input
                else:
                    print(f"'{user_input}' is not valid. Please enter a valid option..\n\n")
                    i += 1
            exit("Wrong Input provided. Script will not exit!!")

        except ValueError:
            print(f"'{user_input}' is not a valid string value..")

def menu(netconnect_obj):

    main_menu = {
        "1": "Collect Logs",
        "2": "Command for Packet Captures (Service Interface)",
        "3": "Collect Debug",
        "4": "Collect SMSTAT Counters",
        "5": "Collect Ouput of Common Commnands",
        #"6": "CC/BC Instance Details",
        "0": "Exit"
    }
    
    debug_menu = {
        "a": "Normal Debug",
        "b": "Firewall Debug",
        "c": "Stop Debug",
        "0": "Exit"
    }
    
    smstat_menu = {
        "a": "MTS Counters",
        "b": "Tunnel Counters",
        "c": "ZPA Counters",
        "d": "MSB Counters",
        "e": "PAC & DNS Counters",
        "f": "Gateway Counters",
        "g": "Config Counters",
        "h": "Traffic Forwarding Rule Counters",
        "i": "Custom Counters",
        "0": "Exit"
    }

    cmd_menu = {
        "a": "Gateway & Tunnel Commands",
        "b": "ZPA Commands",
        "c": "Show Sessions Commands",
        "d": "Show CC Device ID",
        "e": "Show Device Fingerprint",
        "0": "Exit"
    }

    tunnel_gateway_cmd_menu = {
        "a": "Show Gateway",
        "b": "Show Gateway Full",
        "c": "Show Gateway Stats",
        "d": "Show Tunnel",
        "e": "Show Tunnel Full",
        "f": "Show Tunnel Stats",
        "g": "Show Policies",
        "h": "Show Company ID",
        "0": "Exit"
    }
 
    zpa_cmd_menu = {
        "a": "Show ZNF Broker Info",
        "b": "Show ZPAC App Info",
        "c": "Show App Segments",
        "d": "Show DNSM Pool",
        "e": "Show DNSM Map",
        "f": "Show DNSM Pending",
        "0": "Exit"
    }

    session_cmd_menu = {
        "a": "Show CTX",
        "b": "Show More Session",
        "c": "Show FQDN to IP Mappings",
        "d": "Show output of FMT RAW",
        "0": "Exit"
    }

    while True:

        print_menu(main_menu)
        
        main_value = validate_user_input("main_menu")
        
        if main_value == "1":
            cmd_output = netconnect_obj.collect_logs()
            
        elif main_value == "2":
           netconnect_obj.collect_pcap()
        
        elif main_value == "3":
            
            while True:

                print_menu(debug_menu)
                debug_value = validate_user_input("debug_menu")
        
                if debug_value == "a" or debug_value == "A":
                    cmd_output = netconnect_obj.collect_web_debug()
        
                elif debug_value == "b" or debug_value == "B":
                    cmd_output = netconnect_obj.collect_firewall_debug()

                elif debug_value == "c" or debug_value == "C":
                    cmd_output = netconnect_obj.stop_debug()
                    break

                elif debug_value == "0":
                    break
          
        elif main_value == "4":
        
            while True:

                print_menu(smstat_menu)

                smstat_value = validate_user_input("smstat_menu")
        
                if smstat_value == "a" or smstat_value == "A":
                    netconnect_obj.collect_smstat(option=smstat_value)
        
                elif smstat_value == "b" or smstat_value == "B":
                    netconnect_obj.collect_smstat(option=smstat_value)
        
                elif smstat_value == "c" or smstat_value == "C":
                    netconnect_obj.collect_smstat(option=smstat_value)
        
                elif smstat_value == "d" or smstat_value == "D":
                    netconnect_obj.collect_smstat(option=smstat_value)
        
                elif smstat_value == "e" or smstat_value == "E":
                    netconnect_obj.collect_smstat(option=smstat_value)

                elif smstat_value == "f" or smstat_value == "F":
                    netconnect_obj.collect_smstat(option=smstat_value)

                elif smstat_value == "g" or smstat_value == "G":
                    netconnect_obj.collect_smstat(option=smstat_value)

                elif smstat_value == "h" or smstat_value == "H":
                    netconnect_obj.collect_smstat(option=smstat_value)

                elif smstat_value == "i" or smstat_value == "I":
                    netconnect_obj.collect_smstat(option=smstat_value)

                elif smstat_value == "0":
                    break
        
        elif main_value == "5":
            
            while True:

                print_menu(cmd_menu)
                cmd_value = validate_user_input("cmd_menu")

                if cmd_value == "a" or cmd_value == "A":

                    while True:

                        print_menu(tunnel_gateway_cmd_menu)
                        input_value = validate_user_input("tunnel_gateway_cmd_menu")
                        
                        if input_value == "0":
                            break
                        else:
                            netconnect_obj.execute_cmds(main_menu_option=cmd_value, sub_menu_option=input_value)

                elif cmd_value == "b" or cmd_value == "B":

                    while True:

                        print_menu(zpa_cmd_menu)
                        input_value = validate_user_input("zpa_cmd_menu")
                        
                        if input_value == "0":
                            break
                        else:
                            netconnect_obj.execute_cmds(main_menu_option=cmd_value, sub_menu_option=input_value)
        
                elif cmd_value == "c" or cmd_value == "C":

                    while True:

                        print_menu(session_cmd_menu)
                        input_value = validate_user_input("session_cmd_menu")
                        
                        if input_value == "0":
                            break
                        else:
                            netconnect_obj.execute_cmds(main_menu_option=cmd_value, sub_menu_option=input_value)
        
                elif cmd_value == "d" or cmd_value == "D":
                    netconnect_obj.execute_cmds(main_menu_option=cmd_value)
        
                elif cmd_value == "e" or cmd_value == "E":
                    netconnect_obj.execute_cmds(main_menu_option=cmd_value)

                elif cmd_value == "0":
                    break
        
        elif main_value == "6":
            netconnect_obj.instance_details()

        elif main_value == "0":
            netconnect_obj.disconnect()
            break
 