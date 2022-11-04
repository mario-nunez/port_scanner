import json

from ..src.port_scanner import PortScanner 


def _test():
    print('Program started')

    # load variables
    with open(r'./files/target_machines.txt', 'r') as file:
        ip_addrs = [line.strip() for line in file if line.strip()]

    if not ip_addrs:
        print('[-] No targets to scan')
        return

    # scan
    scanner = PortScanner(targets=ip_addrs)
    print('\nScanning ports...')
    report = scanner.scan()

    # create json with the scan results
    report_json = json.dumps(report, indent = 4) 
    with open(r'./output/report.json', 'w') as file:
        file.write(report_json)

    print('\nProgram finished')
    

if __name__ == '__main__':
    _test()
