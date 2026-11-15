# subnetcalc

> [!IMPORTANT]
> **Development takes place on Forgejo. GitHub is a read-only mirror.**
>
> The primary repository is hosted on [Forgejo](https://git.route4all.com/michaelklose/subnetcalc).
>
> All development, issues, and pull requests are managed on Forgejo.
> Please submit contributions and bug reports there.
>
> GitHub is automatically synchronized from Forgejo and serves as an external disaster recovery mirror.

Rewrite of [dreibh/subnetcalc](https://github.com/dreibh/subnetcalc) in Python

Usage examples:  
subnetcalc.py [Address{/{Netmask|Prefix}}]  
subnetcalc.py 10.1.1.1  
subnetcalc.py 10.1.1.1/24  
subnetcalc.py 10.1.1.1/255.255.255.0  

Build binary:  
pyinstaller subnetcalc.py --onefile
