

## How to setup virtual machines



### Virtualbox setup

1. Download virtual box 
2. Download Alpine Linux ISO here: https://www.alpinelinux.org/downloads/ and download the ISO for X86 64 under "Virtual" 
3. Create a new virtual machine in virtual box using the downloaded ISO.
    - Select the path to the downloaded ISO for ISO image 
    - Under Type, select "Linux" 
    - Under Version, select "Other Linux (64-bit)"
    - Use 4 GB for the virtual hard disk 

### Network setup 

4. Temporary internet access for downloading packages. Start up the alpine linux VM and enter "root" as the user login. Then run the following sequence of commands to setup internet access  

``` sh 
ip link set eth0 up 

udhcpc -i eth0 

# to test, run ping 8.8.8.8

```

### Repo Setup

5. Run the following commands to be able to download packages 

``` sh 
setup-apkrepos -c
# This will prompt for the mirror you would would like to use. press "f" 


```

### Allocate Disk Space 

6. Run the following commands to make the changes persist among vm startup   

``` sh 
apk add syslinux blkid

setup-disk
# this will prompt for disk to use. press "enter" 
# it will then prompt for how you would like to use it. enter "sys" 
# enter "y" to if you want to erase the disk 

```

7. On the virtual box GUI with this VM highlighted, go to Settings -> Storage -> Under Controller IDE, press the bar with the ISO name -> press the blue circle icon -> press remove from virtual device 

8. Back in the VM, enter the following command
``` sh 
poweroff

```

9. Restart the VM 

### Make persistant network access

10. Run the following commands to make network access setup automatically  

``` sh 
ip link set lo up 
ip link set eth0 up 
rc-update add networking default 
vi /etc/network/interfaces
# write the following to this file without the pound signs: 
# auto lo
# iface lo inet loopback

# auto eth0 
# iface eth0 inet static
#   address 10.0.2.X  (Use a unique host number at the x)
#   netmask 255.255.255.0
#   gateway 10.0.2.2

reboot 

# test with ping 8.8.8.8
```


### Setup SSH and Port Forwarding

11. Run the following commands to setup ssh 
``` sh 
apk add openssh 

vi /etc/ssh/sshd_config
# Remove the pound sign at "PermitRootLogin" and the text after with "yes"

rc-update add sshd default
rc-service sshd start

# before ssh can work, a password must be set for root
passwd  

```

12. To setup the NAT network and port forwarding, in the Virtual Box GUI, go to File -> Tools -> Network Manager -> Nat Networks -> Create -> Enter A Name -> Disable DHCP
13. Select Port Forwarding, create a new entry with the values:
    - Name: (UNIQUE NAME HERE) Protocol: TCP Host IP: 127.0.0.1 Host Port (UNIQUE PORT HERE) Guest IP: (IP SET FOR ETH0 IN STEP 11) Guest Port: 22
14. Click on your VM -> Settings -> Network -> Attached To: -> Select NAT Network -> Select NAT Network Name 

### SSH Into the VM 

15. The VM can now be connected to via SSH outside of the VM. 
``` bash 
ssh -p <port you used for virtual box port forwarding> root@localhost
```

### Change the Host Name
16. The hostname of the VM can be changed to disnguish between vm sessions. 

``` sh 
setup-hostname
vi /etc/hosts
# Add your hostname on the same line as the line with the 127.0.0.1 ip address 

hostname -F /etc/hostname
```


### Create a copy VM 

17. For creating additional VMs with the same setup, go to the virtual box GUI, right clock on the powered off VM to clone, press Clone
18. Give the VM a new name, then under MAC address policy, select "Generate new MAC addresses ..." 
19. Select "Full Clone" 

20. Go to step 10 to give it a unique IP address in the NAT network, step 13 to setup port forwarding for this VM, and step 16 to setup a host name 


















