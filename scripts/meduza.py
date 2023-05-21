import argparse
import json
import os

import frida
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import NameOID, ExtensionOID


def str_or_none(value):
    if value.lower() == "none":
        return None
    return value


class NoArgAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        # If the option has a blank input, set its value to None
        if len(values) == 0:
            setattr(namespace, self.dest, True)
        else:
            setattr(namespace, self.dest, values)


class CertSpoofer:
    NAME = "MEDUZA iOS SSL unpinning tool\nby Dima Kovalenko (@kov4l3nko)"

    HELP = """
    Usage:
        $ python3 meduza.py -l
        to list applications
        
        $ python3 meduza.py -s -b <app name of id> -o path/to/frida/script.js
        to spawn an application and generate an SSL (un)pinning Frida script
        
        $ python3 meduza.py -a -b <app name of id> -o path/to/frida/script.js
        to attach an application and generate an SSL (un)pinning Frida script
        
        $ python3 meduza.py -s -b <app name of id> -o path/to/frida/script.js -p payload.js
        to spawn an application and generate an SSL (un)pinning Frida script with a specially 
        crafted payload (the payload.js should be placed alongside with the py file)
        
        $ python3 meduza.py -a -b <app name of id> -o path/to/frida/script.js -p payload.js
        to attach an application and generate an SSL (un)pinning Frida script with a specially 
        crafted payload (the payload.js should be placed alongside with the py file)
    """

    CERTS = {}
    DOMAIN_CERTS = {}
    DOMAINS = {}

    @staticmethod
    def print_help_and_exit():
        print(CertSpoofer.HELP)
        exit()

    def list_applications(self, print_result=False, device_id=None):
        if device_id is None:
            print("[*] Waiting for an iOS device connected to USB...")
            self.device = frida.get_usb_device()
        else:
            print(f"[*] Waiting for an iOS device: {device_id} ...")
            self.device = frida.get_device(device_id)
        applications = self.device.enumerate_applications()
        if print_result:
            print("[*] A list of installed applications:")
            for app in applications:
                print("\t{} {} ({}){}".format(
                    "-" if app.pid == 0 else "+",
                    app.name,
                    app.identifier,
                    " is running, pid={}".format(app.pid) if app.pid != 0 else "")
                )
        return applications

    def parse_command_line(self):
        if self.args.list_applications:
            # List applications
            if self.args.device:
                # List application on the device connected via Remote
                self.list_applications(print_result=True, device_id=self.args.device)
                exit()
            else:
                # List application on the device connected to USB
                self.list_applications(print_result=True)
                exit()
        else:
            self.spawn = False if self.args.attach else True
            app_name_or_id = self.args.bundle_identifier
            applications = self.list_applications(
                device_id=self.args.device) if self.args.device else self.list_applications()
            found = False
            for app in applications:
                if app.name == app_name_or_id or app.identifier == app_name_or_id:
                    found = True
                    self.app = app

            if not found:
                print("[*] Application {} not found! Use -l to list installed/running apps".format(app_name_or_id))
                CertSpoofer.print_help_and_exit()

            if (not self.spawn) and (self.app.pid == 0):
                print(
                    "[*] {} is not running. Please open the app and try again "
                    "or use -s to spawn the app with the script"
                    .format(app_name_or_id)
                )
                CertSpoofer.print_help_and_exit()

            # Parse 3rd argument
            self.js_output_path = os.path.abspath(os.path.expandvars(os.path.expanduser(self.args.output)))
            if os.path.exists(self.js_output_path):
                print(
                    "[*] {} already exists, please specify a non-existing file in already existing directory, "
                    "the file will be created"
                    .format(self.js_output_path)
                )
                exit()

            if not os.path.exists(os.path.dirname(self.js_output_path)):
                print(
                    "[*] The dir {} does not exists, please specify a non-existing file in already existing directory, "
                    "it will be created"
                    .format(self.js_output_path)
                )
                exit()

            if self.args.payload:
                self.payload = self.args.payload

    def run_app(self):
        # Get app's pid
        if self.spawn:
            print("[*] Spawning {}...".format(self.app.identifier))
            pid = self.device.spawn([self.app.identifier])
        else:
            pid = self.app.pid
        # Create session
        print("[*] Attaching to {}...".format(self.app.identifier))
        self.session = self.device.attach(pid)
        # Read the JS scripts
        print("[*] Reading JS payload {}...".format(self.payload))
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.payload)
        # Read the JS code
        js_file_handle = open(script_path, "r")
        js_code = js_file_handle.read()
        js_file_handle.close()
        # Create script and load it to the process
        print("[*] Injecting JS payload to the process...")
        script = self.session.create_script(js_code)
        script.on("message", CertSpoofer.on_message)
        script.load()
        # Resume the process, if the script just spawned it
        if self.spawn:
            print("[*] Resuming the application...")
            self.device.resume(pid)

    @staticmethod
    def on_message(message, data):
        # Process the data sent by the script
        if message["type"] == "send":
            payload = message['payload']
            if payload.startswith("["):
                print(payload)
            elif payload not in CertSpoofer.CERTS:
                # Get the certificate
                CertSpoofer.CERTS[payload] = list(data)
                print("[*] Got another certificate, its raw SHA256 hash: {}".format(payload))
                # Parse the certificate, get all the common names
                cert = x509.load_der_x509_certificate(data, default_backend())
                cns = []
                for i in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                    t = i.value
                    # If t does not contain spaces, but it contains dots, it's probably a domain name
                    if (" " not in t) and ("." in t):
                        cns.append(t)
                try:
                    cns += cert.extensions.get_extension_for_oid(
                        ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
                except:
                    pass
                # Remove duplicates
                cns = list(dict.fromkeys(cns))
                # Add the domain to the list if at least one domain name found
                if len(cns) > 0:
                    CertSpoofer.DOMAIN_CERTS[payload] = CertSpoofer.CERTS[payload]
                # Set domain name/hash pairs
                for domain in cns:
                    CertSpoofer.DOMAINS[domain] = payload
                # Print the name(s)
                if len(cns) > 0:
                    print("\t{}".format("\n\t".join(cns)))
        elif message['type'] == 'error':
            print("[!] Error in the JS payload:")
            print(message['stack'])

    def save_to_js(self):
        print("[*] Saving the result to {}...".format(self.js_output_path))
        # Reading the template
        template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "meduza-template.js")
        f = open(template_path, "r")
        template = f.read()
        f.close()
        # Serialize the data
        domains = json.dumps(CertSpoofer.DOMAINS, indent=4)
        certs = json.dumps(CertSpoofer.DOMAIN_CERTS)
        # Write the result to the file
        f = open(self.js_output_path, "w")
        f.write(
            "/*\n\n\tThe script was autogenerated by MEDUZA SSL unpinning tool (https://github.com/jayluxferro/MEDUZA)\n\n*/\n\n")
        f.write("var certs = {};\n\n".format(certs))
        f.write("var domains = {};\n\n".format(domains))
        f.write(template)
        f.close()
        print("[*] Done!")

    def __init__(self, args):
        # Init object fields with their default values
        self.args = args
        self.spawn = None
        self.app = None
        self.js_output_path = None
        self.device = None
        self.session = None
        self.payload = "meduza.js"
        # Print name/version
        print("{}\n{}\n".format(CertSpoofer.NAME, "=" * len(CertSpoofer.NAME)))
        # Parse command line
        self.parse_command_line()
        # Run the app with the Frida script
        self.run_app()
        # Wait for complete
        input("[*] Press ENTER to complete (you can do it anytime)...\n")
        self.session.detach()
        # Save results to the file
        self.save_to_js()


# ArgumentParser object
parser = argparse.ArgumentParser()

# Add CLI options
parser.add_argument("-l", "--list-applications", nargs=0, action=NoArgAction, help="List applications")
parser.add_argument("-d", "--device", type=str_or_none, default="None", help="Specify a device ID")
parser.add_argument("-b", "--bundle-identifier", type=str_or_none, default="None",
                    help="Application name or its bundle identifier")

attach_or_spawn = parser.add_mutually_exclusive_group()
attach_or_spawn.add_argument("-a", "--attach", action="store_true",
                             help="Attach to the running application")
attach_or_spawn.add_argument("-s", "--spawn", action="store_true",
                             help="Spawn the application")
attach_or_spawn.set_defaults(spawn=True)

parser.add_argument("-o", "--output", type=str_or_none, default="None", help="Path to write the Frida script file")
parser.add_argument("-p", "--payload", type=str_or_none, default="None", help="Payload")

CertSpoofer(args=parser.parse_args())
