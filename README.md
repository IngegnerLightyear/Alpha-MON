![A-mon Logo](https://github.com/IngegnerLightyear/Alpha-MON/blob/master/A-mon_logo.png)
# ⍺-MON
## Anonymized Passive Traffic Monitoring

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
* `PCI_ADDR`: The port(s) to be ignored from the console information.

The parameters before `--` are DPDK enviroment related. See its guide for further explaination.

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

You can manage MAC addresses by specifying  in the `[group]` section of the INI file:
*  `anon_mac = 0`: the module is disabled;
*  `anon_mac = 1`: delets the MAC addresses;
*  `anon_mac = 2`: replaces the MAC addresses with a timestamp.

### IP Anonymization

You can anonymize IP address using the [CryptoPan](https://www.cc.gatech.edu/computing/Networking/projects/cryptopan/) algorithm that obfuscates IP address in a prefix-preserving manner. To enable it, you need to set `anon_ip = 1` in the `[group]` section of the INI file.

Then, you have to decide the policy for the encryption key by setting `key_mode` to `static` or `rotate`.
If you choose `static`, you must set a `key`. If you choose `rotate`, you must specify a `rotation_delay` in seconds.

Finally, you must specify the networks to anonymize, writing a subnet file, and specifying its path in the `anon_subnet_file` parameter. The file must contain a subnet per row in the form `subnet/prefix`, e.g., `192.168.0.0/16`.

In addition, it is possible to process IP addresses using the anonymization engine described for L4-7.

### L4-7 Anonymization

#### Engine

You must provide into the configuration file a policy to enable the ⍺-Anonymization Engine by setting `engine = 1`.
At this point it is possible to enable, in the form of a whitelist, which protocols must undergo the anonymization process and which can be ignored: just enter the value `0/1` in correspondence with the supported protocol.
Finally, if  `engine = 1`, you have to set the `alpha` and `delta` values:
* `alpha` represents the number of unique users linked to the same name;
* `delta` is time interval.

The potentially sensitive information will be obfuscated if the number of users linked to the same name is less than `alpha` in the `delta` time interval. Otherwise it will be allowed to pass and will be considered as known.

#### Flow Management

By default the `flow management`module is activated, in order to keep the behavior of the modules consistent within the same flow:
* if the first packet was subject to anonymization (since `alpha` is below threshold), the rest of the flow will be subject to anonymization, until its closure or expiration;
* if the first packet was not subject to anonymization (since `alpha` is above the threshold), no packet of the flow will be subject to anonymization, until its closure or expiration;

#### Anonymization modules

If the `engine` is enabled, a `DPI Module` is deployed in order to detect the protocol contained in the current packet.
The following modules can be deployed to apply ⍺-Anonymization:
* `External IP Managment`: if enabled, it will apply the ⍺-Anonymization on external IP addresses consistently, otherwise the anonymization will be performed only by CryptoPan;
* `Dns Protocol Managment`: if triggered, hides all kind of names (preserving their structure, as defined in RFCs) inside the `DNS` queries and responses and obfuscates IP address in a prefix-preserving manner;
* `Tls Protocol Managment`: if triggered, hides the SNI inside the `TLS Client Hello` packet;
* `Http Protocol Managment`: if triggred, hides fields (preserving their structure, as defined in RFCs) inside `HTTP` packets that can lead to a particular web page;
* `Unsafe protocol`: is triggered automatically if the protocol is not encrypted or is "unknown" (it doesn't match the ones managed by the implemented modules), deleting the packet payload.

## INI file entries
You must provide a `-c` argument, containing the path of a INI file containing the configuration parameters.
```
[general]
mempool_elem_nb = 32768                                 ; size of the mempool for packets
num_config = 1                                          ; number of available configs

[group]
anon_mac = 0/1/2                                        ; Enable/disable MAC address rewrite
anon_ip = 0/1                                           ; Enable/disable IP address anonymization
key_mode = static                                       ; Use a static or rotating key
key = rK3bSQ7z7VlyEJqYXKgP8n7AAjSes7tPeoJV9gyZ0v4=      ; Static key
rotation_delay = 86400                                  ; Delay for rotating the key
anon_subnet_file = sample-conf/subnets.txt              ; File with subnets to anonymize
engine = 0/1                                            ; Enable anonymization engine
    external_ip = 0/1                                   ; Enable ⍺-anon on external IP addresses
    dns = 0/1                                           ; Enable ⍺-anon on dns
    tls = 0/1                                           ; Enable ⍺-anon on tls
    http = 0/1                                          ; Enable ⍺-anon on http
alpha = 3                                               ; Alpha value for anonymization
delta = 60                                              ; Delta time for Alpha-Anonymization

[interfaces_mappings]
<pci_address_in> = <pci_address_out>                    ; Describe how packets flow
 
[interface_conf]
<pci_address_out> = #group                              : Describe output interface config

[end]

```



