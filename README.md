# ⍺-MON
⍺-MON anonymizes network traffic in real time. It is based on DPDK.
This software process network traffic on input interfaces to remove privacy sensitive information transmitted in clear by protocols.
Then, it transmits anonymized traffic on the output interfaces.
This software is higly configurable in terms of:
* processing power;
* anonymized fields;
* anonymization level;
* topology.

## Dependencies
You need [DPDK](http://dpdk.org/) (version 19).
Once installed, please load the kernel modules, reserve a suitable number of hugepages to DPDK, and finally bind the desired NICs to DPDK drivers.

You can install this software with:
``` 
git clone https://github.com/IngegnerLightyear/A-MON.git
```

And compile with:
```
make
```

## Run
Just run with:
```
sudo ./build/a_mon -c COREMASK [-b PCI_ADDR] -- -c <ini_file>
```
* `COREMASK`: The core where to bind the program. **It needs consecutive cores starting from Core0**
* `PCI_ADDR`: The port(s) where to send. If not present, it sends the same traffic to every port.

The parameters before `--` are DPDK enviroment related. See its guide for further explaination.

By default, it uses all cores and NICs of your system. Check DPDK parameters to control this behavior.

## How it works

⍺-MON reads packets from input NICs, processes them, and sends them on the output port.

### Input/Output mapping

You have to specify a mapping from any input NIC to a NIC used for output. This specifies how packets are routed by ⍺-MON.
The configuration is extremely flexible, in fact any type of configuration is allowed:
* one-to-one;
* one-to-many;
* many-to-one.

Mappings are specified in the INI file under the section `[interface_mapping]`, in the form `<pci_address_in> = <pci_address_out>`.

### MAC Anonymization

You can delete MAC addresses by specifying `anon_mac = 1 ` in the `[group]` section of the INI file.

### IP Anonymization

You can anonymize IP address using the [CryptoPan](https://www.cc.gatech.edu/computing/Networking/projects/cryptopan/) algorithm that obfuscates IP address in a prefix-preserving manner. To enable it, you need to set `anon_ip = 1` in the `[group]` section of the INI file.

Then, you have to decide the policy for the encryption key by setting `key_mode` to `static` or `rotate`.
If you choose `static`, you must set a `key`. If you choose `rotate`, you must specify a `rotation_delay` in seconds.

Finally, you must specify the networks to anonymize, writing a subnet file, and specifying its path in the `anon_subnet_file` parameter. The file must contain a subnet per row in the form `subnet/prefix`, e.g., `192.168.0.0/16`.

### L4-7 Anonymization

You must provide into the configuration file a policy to enable the ⍺-Anonymization Engine by setting `engine = 1`.
At this point it is possible to enable, in the form of a whitelist, which protocols must undergo the anonymization process and which can be ignored: just enter the value `0/1` in correspondence with the supported protocol.
Finally, if  `engine = 1`, you have to set the alpha and delta values:
* alpha represents the number of unique users linked to the same name;
* delta is time interval.

The name will be obfuscated if the number of users linked to the same name is less than alpha in the delta time interval. Otherwise it will be allowed to pass and will be considered as a known name.

## INI file entries
You must provide a `-c` argument, containing the path of a INI file containing the configuration parameters.
```
[general]
mempool_elem_nb = 32768                                 ; size of the mempool for packets
num_config = 1                                          ; number of available configs

[group]
anon_mac = 0/1                                          ; Enable/disable MAC address rewrite
anon_ip = 0/1                                           ; Enable/disable IP address anonymization
key_mode = static                                       ; Use a static or rotating key
key = rK3bSQ7z7VlyEJqYXKgP8n7AAjSes7tPeoJV9gyZ0v4=      ; Static key
rotation_delay = 86400                                  ; Delay for rotating the key
anon_subnet_file = sample-conf/subnets.txt              ; File with subnets to anonymize
engine = 0/1                                            ; Enable anonymization engine
    dns = 0/1                                           ; Enable ⍺-anon on dns
    tls = 0/1                                           ; Enable ⍺-anon on tls
alpha = 3                                               ; Alpha value for anonymization
delta = 60                                              ; Delta time for Alpha-Anonymization

[interfaces_mappings]
<pci_address_in> = <pci_address_out>                    ; Describe how packets flow
 
[interface_conf]
<pci_address_out> = #group                              : Describe output interface config

[end]

```



