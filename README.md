NATlab is a testbed for NAT traversal software. It intercepts packets
before Linux's NAT implementation can process them, and does its own
translation according to configurable policies. This enables NATlab to
emulate any NAT behavior you desire.

Combined with something like docker-compose, you can construct complex
network topologies, featuring multiple NAT gateways with different
behaviors, and see how well your software is able to traverse them.

## Notation

We write ip:port combinations as `X:x`, `X1:x1`, `Y2:y2` and so
forth. We write a NAT mapping as `X1:x1 <> X1':x1'`, meaning "the LAN
source ip:port `X1:x1` is rewritten to `X1':x1'` as packets go through
the NAT box".

## NAT behaviors

NATlab implements a configurable NAT gateway, with configuration knobs
for each of the behaviors identified by [RFC
4787](https://tools.ietf.org/html/rfc4787). By varying these knobs,
you can emulate a wide variety of NAT devices.

In general, the questions we're trying to answer are:

 - When a packet shows up on the LAN interface, what do its IPs and
   ports get translated to when leaving on the WAN interface?
 - When a packet shows up on the WAN interface, where does it go on
   the LAN interface - if anywhere? (it might get dropped)

The specific knobs offered by NATlab are as follows. We'll use `REQ-x`
to reference each behavior, although the RFC uses `REQ-x` to specify
what a nice NAT box _should_ do, we use it to describe all possible
behaviors.

### REQ-1: Mapping reuse behavior

When a LAN client sends packets from `X1:x1`, the NAT box assigns a
NAT mapping that rewrites the source to `X1':x1'` on the way out. The
LAN client then continues to send from `X1:x1`, but varies the
destination IP and/or port.

 1. **Endpoint-Independent**: The mapping `X1:x1 <> X1':x1'` is reused
    regardless of the destination address.

 2. **Address-Dependent**: The mapping `X1:x1 <> X1':x1` is reused as
    long as the destination IP address is the same.
    
 3. **Address-And-Port-Dependent**: The mapping `X1:x1 <> X1':x1'` is
    reused as long as both the destination IP and destination port are
    the same.

RFC recommends **Endpoint-Independent** behavior.

### REQ-2: IP address pooling

Assume the NAT box has multiple public IP addresses it can choose from
when creating new NAT mappings. A LAN client sends packets from `X1`,
on various source ports and to various destinations. What public IP(s)
will be used for mappings?

 1. **Arbitrary**: different sessions from `X1` may get different
    public IPs `X1'`, `X2'`, ....
 2. **Paired**: all sessions from `X1` use a single public IP
    `X1'`. If `X1'` has no free ports to use for a new mapping, new
    sessions are dropped.
 3. **Soft-Paired**: all sessions from `X1` use a single public IP
    `X1'`. If `X1'` has no free ports to use for a new mapping, ports
    on other IPs may be used.

RFC recommends **Paired** behavior, but notes that many enterprise NAT
gateways use **Arbitrary** behavior "for security reasons" (i.e. wooly
thinking).

### REQ-3: Port assignment

When a new NAT mapping `X1:x1 <> X1':x1'` needs to be created, how
does the NAT box pick `x1'`?

 1. **Port-Overloading**: The NAT box will set `x1' = x1`. If this
    results in a collision, the previous mapping is deleted.
 2. **Port-Preserving**: The NAT box will attempt to set `x1' =
    x1`. In case of collision, the NAT box will pick some other `x1'`.
 3. **Arbitrary**: The NAT box will not attempt to keep `x1' = x1` at
    all.

REQ-3 does not specify what source IP to use. It's allowable to pick
`x1'` on any available public IP, subject to the constraints of the
other settings.

RFC recommends anything but **Port-Overloading**, for the obvious
reason that it breaks stuff hilariously.

### REQ-4: Port Parity

When picking a port `x1'` to map `X1:x1`, does the NAT box attempt to
keep `LSB(x1') == LSB(x1)`, i.e. map even ports to even ports and odd
ports to odd ports?

This is a silly distinction designed to placate ancient RTP clients,
so NATlab doesn't implement it.

### REQ-5: Mapping refresh timer

How long can a mapping go without seeing "qualifying traffic" (see
REQ-6) before it gets deleted?

RFC recommends 5 minutes, and begs vendors to not set it lower than 2
minutes. Exceptions exist for certain types of traffic, e.g. DNS can
have much shorter timeouts. NATlab doesn't (yet?) support overriding
the timer by port.

### REQ-6: Qualifying packets for mapping refresh

What packets trigger a renewal of the NAT mapping's lease?

 1. **Outbound-Only**: only packets going from LAN to WAN refresh the
    mapping.
 2. **Inbound-Only**: only packets going from WAN to LAN refresh the
    mapping.
 3. **Both**: packets going in either direction refresh the mapping.

RFC recommends **Outbound-Only** at minimum, ideally **Both** (but
points out that **Both** may enable a resource DoS on the NAT box, so
"for security reasons" expect **Outbound-Only** to be the norm)

### REQ-7: Internal/External address conflicts

This specifies that if LAN and WAN have address collisions, the NAT
box should handle this gracefully. NATlab doesn't implement this at
all, as afaict this is a theoretical concern rather than a practical
one.

### REQ-8: Filtering Behavior

When packets are traversing the NAT from WAN to LAN and match a NAT
mapping, what packets are permitted to flow back to the LAN client?

 1. **Endpoint-Independent**: all packets that matched the NAT mapping
    can flow.
 2. **Address-Dependent**: packets from `Y:*` can only flow if the LAN
    client has previously sent packets to `Y`.
 3. **Address-And-Port-Dependent**: packets from `Y:y` can only flow
    if the LAN client has previously sent packets to `Y:y`.

RFC recommends either **Endpoint-Independent** or
**Address-Dependent**, depending on paranoia levels.

### REQ-9: Hairpinning behavior

If two clients `X1:x1` and `X2:x2` are on the same LAN, can they use
each other's public addresses `X1':x1'` and `X2':x2'` and hairpin
through the NAT box?

 1. **No**: hairpinning is not allowed, packets that attempt to
    hairpin are dropped.
 2. **Internal-Source**: hairpinning is allowed. Packets are delivered
    with the internal `ip:port` as the source.
 3. **External-Source**: hairpinning is allowed. Packets are delivered
    with the external `ip:port` as the source.

RFC requires **External-Source** behavior.

### REQ-10: ALG behavior

This requirement has to do with NATs having explicit behavioral
support for certain protocols (e.g. VOIP). The RFC says to disable all
ALGs, and NATlab doesn't implement any.

### REQ-11: Determinism

Roughly, this section says NATs shouldn't vary one REQ- behavior based
on the outcome of another REQ- behavior. Some specific examples are
given, but each one would have to be encoded as another sub-behavior
of the appropriate REQ-.

For now, NATlab's implementation is deterministic according to this
section.

### REQ-12: ICMP support

Does the NAT box correctly rewrite and forward ICMP messages that
pertain to an active NATed session?

 1. **Yes**: ICMP messages whose payload contains fragments of UDP
    packets are correctly rewritten and forwarded across the NAT.
 2. **No**: ICMP messages are eaten by the NAT box.

RFC recommends **Yes**.

### REQ-13, REQ-14: IP Fragmentation

These are just a requirement that the NAT gateway should handle IP
fragmentation correctly. DF=1 packets should result in ICMP
Fragmentation Needed + drop, DF=0 should result in fragmentation.

NATlab relies on the linux kernel to do this right.

### XXX-1: NAT helper protocols

This isn't from the RFC, but there are a variety of "NAT helper"
protocols that a client can use to explicitly create a port
mapping. Eventually, we'd like NATlab to support them. They are:

 1. **UPnP IGDP**: a horror in XML, SOAP and UDP. Never seen
    implemented cleanly, because one does not implement cursed
    protocols cleanly.
 2. **NAT-PMP**: Apple's surprising contribution to not being
    completely impossible to implement. It's really quite nice.
 3. **PCP**: Evolution of NAT-PMP, similarly nice. Also includes logic
    for NAT64 and other esoterica.
