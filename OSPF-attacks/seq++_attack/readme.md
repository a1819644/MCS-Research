## writter by Anoop Kumar Kushwaha



## Seq++ attack
According to RFC in section-13.1, the LSA flooded by the router to its neighbour is considered to be more recent by its neighbours if the LS sequence number, 
LS checksum is greater than the install current(currently installed in router’s database)[5] and according to RFC in section 13.2, installa- tion of LSA occurs only if the new LSA content compare to 
to installed("Note that this excludes changes in LS Sequence Number and LS Checksum") ones [5]. According to Wang et.al., an attacker can take an advantage of this vulnerability by increasing the LS sequence number by 1 and changing any, one of the LSA content such as LSA type(between 1 to 5) or link state metric and re-flood the malformed LSA on the network on behalf of the victim router to create the tempo- rary instability in the network [6, 5]. As a result, other routers will install into their database and flood this updated infor- mation. Upon receiving malformed information, the victim router will originate the new LSA with the larger sequence number and flood the new correct to its neighbour[7].

## Assumptions
    • An attacker has gotten an access to the one of the router on the AS [8]


## Orchestration
```
    1 : We start by intercepting the LSA packet sent by the victim router(n5),where we were sitting on the imper- sonated router n1 fig.
    2 : We craft the forged packet by changing the link state metric of the link between the n5 and n6 router( fig) to 30 from 10 and increase the sequence number by 1.
    3 : In our last step, we flood(multicast address 224.0.0.5) the crafted packet on behalf of the victim with gap of 1 sec. The time delay must be followed otherwise the neighbors won’t install the packet sent by us as describe by RFC in Architectural Constant
```

## Observer behavior from attack:
 We observed that neigh- bours of victim router are installing the forged packet and flooding the updated information with their neighbours. Eventually, the victim routers receive incorrect information about themselves which causes them to flood the new LSA packet containing a larger sequence and correct informa- tion(from our example n5 is increasing the seq > forged pat seq and correcting the link to 10).


## Impacts
 Upon sending the crafted packet, we were able create the network instability in chosen topology(fig). We confirmed by ping the router from n6 to n3 router, where ping packet was dropped during the attack.



![topology](seq.png)


## Work references
• https://youtu.be/f-k8HmYSQNA

##  To Run
    sudo python3 seq++.py -v [victim ip] -n [attacker location] -i [interface]
    Example: sudo python3 seq++.py -v 10.0.2.1 -n 10.0.0.1 -i veth6.0.1



