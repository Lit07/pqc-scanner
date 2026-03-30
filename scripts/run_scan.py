from scanner.nmap_scanner import NmapScanner

scanner = NmapScanner()
result = scanner.scan("scanme.nmap.org")

print(result)