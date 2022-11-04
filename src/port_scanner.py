from datetime import datetime
import socket


class PortScanner:

    TEST_PORT = 80
    COMMON_PORTS = [20, 21, 22, 23, 25, 53, 69, 80, 156, 443, 500, 8080, 8443]

    def __init__(self, targets=None, ports=COMMON_PORTS):
        self.targets = targets
        self.ports = ports
        self.report = []

    def format_info(self, target, reached, reason, target_data):
        open_ports = [{"port": i[0], "banner": i[1]} for i in target_data]
        target_info = {
            "target": target,
            "state": {
                "reached": reached,
                "reason": reason
            },
            "open_ports": open_ports,
            "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        return target_info

    def scan_port(self, target, port):
            """
            Scan a single port of a target machine.
            """
            try:
                sock = socket.socket()
                sock.settimeout(0.2)
                sock.connect((target, port))
                try:
                    banner = sock.recv(1024).decode().strip('\n').strip('\r')
                except socket.timeout:
                    banner = ''
                sock.close()
                return port, banner
            except TimeoutError as e:
                return None, 'ignore'
            except (ConnectionRefusedError, OSError, socket.gaierror) as e:
                return False, e.strerror

    def reach_target(self, target):
        """
        Try to reach a target machine
        """
        p, i = self.scan_port(target, self.TEST_PORT)
        if p is False:
            reached = False
            reason = i
        else:
            reached = True
            reason = ''
        return reached, reason

    def scan(self):
        """
        Scan ports of target machines and return a report with the information
        collected.
        """
        # clean data obtained in previous executions
        self.report = []
        for target in self.targets:
            reached, reason = self.reach_target(target)
            target_data = []
            if reached is True:
                for port in self.ports:
                    open_port, banner = self.scan_port(target, port)
                    if open_port:
                        target_data.append((open_port, banner))

            target_info = self.format_info(target, reached, reason, target_data)
            self.report.append(target_info)

        return self.report
