

## How to setup virtual machines



### VBOX SETUP 

1. Download virtual box 
2. Download Alpine Linux ISO here: https://www.alpinelinux.org/downloads/ and download the ISO for X86 64 under "Virtual" 
3. Create a new virtual machine in virtual box using the downloaded ISO.
    - Select the path to the downloaded ISO for ISO image 
    - Under Type, select "Linux" 
    - Under Version, select "Other Linux (64-bit)"
    - Use 4 GB for the virtual hard disk 

4. To make SSH work for virtual box, On the virtual box GUI with this vm highlighted, go to settings -> network -> advanced -> port forwarding and create a new entry with the following entries: 
    - name: <unique name> protocol: TCP host ip: 127.0.0.1 host port: <unique port> guest ip: LEAVE BLANK guest port: 22


### NETWORK SETUP 

5. Start up the alpine linux VM and enter "root" as the user login. Then run the following sequence of commands to setup internet access  

``` sh 
ip link set lo up 
ip link set eth0 up 

udhcpc -i eth0 

# to test, run ping 8.8.8.8

```

### REPO SETUP 

6. Run the following commands to be able to download packages 

``` sh 
setup-apkrepos -c
# This will prompt for the mirror you would would like to use. press "f" 


```

### ALLOCATE NON-VOLATILE SPACE 

7. Run the following commands to make the changes persist among vm startup   

``` sh 
apk add syslinux blkid

setup-disk
# this will prompt for disk to use. press "enter" 
# it will then prompt for how you would like to use it. enter "sys" 
# enter "y" to if you want to erase the disk 

```

8. On the virtual box GUI with this VM highlighted, go to Settings -> Storage -> Under Controller IDE, press the bar with the ISO name -> press the blue circle icon -> press remove from virtual device 

9. Back in the VM, enter the following command
``` sh 
poweroff

```

10. Restart the VM 

### MAKE NETWORK ACCESS PERSISTANT 

11. Run the following commands to make network access setup automatically  

``` sh 
ip link set lo up 
ip link set eth0 up 
rc-update add networking default 
vi /etc/network/interfaces
# write the following to this file: auto lo
#                                   iface lo inet loopback

#                                   auto eth0 
#                                   iface eth0 inet dhcp 

reboot 

# test with ping 8.8.8.8
```


### SETUP SSH 

12. Run the following commands to setup ssh 
``` sh 
apk add openssh 

vi /etc/ssh/sshd_config
# Remove the pound sign at "PermitRootLogin" and the text after with "yes"

rc-update add sshd default
rc-service sshd start

# before ssh can work, a password must be set for root
passwd  

```

### CONNECT TO THE VM VIA SSH 

13. The VM can now be connected to via SSH outside of the VM. 
``` bash 
ssh -p <port you used for virtual box port forwarding> root@localhost
```

### CHANGE THE HOST NAME 
14. The hostname of the VM can be changed to disnguish between vm sessions. 

``` sh 
setup-hostname
vi /etc/hosts
# Add your hostname on the same line as the line with the 127.0.0.1 ip address 

hostname -F /etc/hostname
```


### CREATE A COPY VM 

15. For creating additional VMs with the same setup, go to the virtual box GUI, right clock on the powered off VM to clone, press Clone
16. Give the VM a new name, then under MAC address policy, select "Generate new MAC addresses ..." 
17. Select "Full Clone" 

18. Go to step 14 to give it a new hostname and step 4 to change the ssh port to use  


















