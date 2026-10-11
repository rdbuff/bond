Windows Filtering Platform kill switch, copied from
golang.zx2c4.com/wireguard/windows v1.1.1 tunnel/firewall (MIT, © WireGuard LLC).

Change: the "permit this process" rule matches on the executable path only;
upstream additionally requires a Windows service SID, which an ordinary
elevated app like Bond.exe does not have. The WFP session is dynamic, so all
filters disappear when the process exits, even on a crash.
