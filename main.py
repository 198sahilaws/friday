from menu import pre_login_data, menu
from net_class import NetworkDevice
import logging

def main():
    session_details = pre_login_data()
    if "ec_ip" in session_details.keys() and "ec_ssh_key" in session_details.keys():
        cc1 = NetworkDevice(cloud=session_details["cloud_name"], org_id=session_details["company"], key_file=session_details["ec_ssh_key"], ip_address=session_details["ec_ip"], port=session_details["ssh_port"])
    else:
        cc1 = NetworkDevice(cloud=session_details["cloud_name"], org_id=session_details["company"], port=session_details["ssh_port"])

    menu(cc1)

if __name__ == "__main__":
    main()