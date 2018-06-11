Title: Breaking ledgerctf's AES white-box challenge
Date: 2018-05-17 11:52
Tags: reverse-engineering, ledgerctf, whitebox
Authors: Axel "0vercl0k" Souchet

# Introduction

About a month ago, my mate [b0n0n](https://twitter.com/b0n0n) was working on the [ledgerctf](https://www.ledger.fr/ctf2018/) puzzles and challenged me to have a look at the *ctf2* binary. I eventually did and this blogpost discusses the protection scheme and how I broke it. Before diving in though, here is a bit of background.

[ledger](https://www.ledger.fr/) is a french security company funded in 2014 that is specialized in cryptography, cryptocurrencies and hardware. They recently put up online three different puzzles to celebrate the official launch of their [bug bounty program](https://www.ledger.fr/bounty-program/). The second challenge called *ctf2* is the one we will be discussing today. *ctf2* is an ELF64 binary that is available [here](https://drive.google.com/open?id=1UPLe3V5Jt3SMqZe4ZIFcnWydSqUyI4Ao) for download (if you want to follow at home). The binary is about 11MB, written in C++ and even has symbols; great.

Let's do it!

<!-- PELICAN_END_SUMMARY -->

[TOC]

# The big picture

## Recon

The very first thing I'm sure you've seen is how much data is in the binary as seen in the below picture. It means that either the binary is packed and IDA is struggling to recognize pieces of the binary as code, or it is actually real data.

<center>![ida.png](/images/breaking_ledgerctfs_ctf2_aes_whitebox_challenge/ida.png)</center>

As we also already know that the binary hasn't been stripped, the first hypothesis is most likely wrong. By skimming through the code in the disassembler, nothing really stands out; everything looks healthy. No sign of obfuscation, code-encryption or packing of any sorts. Pretty sure we are looking at a pure reverse-engineering challenge at this point, smooth sailing!

## Diffusion

The binary expects a serial as input which is a string composed of 32 hex characters, like this one: `00112233445566778899AABBCCDDEEFF`. Then, there is a 16 rounds loop that walks the serial character by character and builds 15 blobs of 16 bytes long each; I call them `i0`, `i1`, .., `i14` (as it's very self explanatory). Each round of this loop initializes one byte of every `i`'s (hence the 16 rounds). The current input serial byte is sent through a huge substitution box (that I called `sbx` and that it is 11534336 bytes long). This basically diffuses the input serial in those blobs. If the explanation above wasn't clear enough or something; here is what it looks like in prettyfied C code:

```C
while(Idx < 16) {
  sbx++;
  char CurrentByteString[3] = {
    Serial[Idx],
    Serial[Idx + 1],
    0
  };
  Idx += 2LL;
  uint8_t CurrentByte = strtol(CurrentByteString, 0LL, 16);
  i0[sbx[-1]] = CurrentByte;
  i1[sbx[15]] = CurrentByte;
  i2[sbx[31]] = CurrentByte;
  i3[sbx[47]] = CurrentByte;
  i4[sbx[63]] = CurrentByte;
  i5[sbx[79]] = CurrentByte;
  i6[sbx[95]] = CurrentByte;
  i7[sbx[111]] = CurrentByte;
  i8[sbx[127]] = CurrentByte;
  i9[sbx[143]] = CurrentByte;
  i10[sbx[159]] = CurrentByte;
  i11[sbx[175]] = CurrentByte;
  i12[sbx[191]] = CurrentByte;
  i13[sbx[207]] = CurrentByte;
  i14[sbx[223]] = CurrentByte;
}
```

## Confusion

After the above, there is now a bunch of stuff happening that don't necessarily make a whole lot of sense at the time of reverse-engineering. As far as I am concerned though, it also doesn't sound too concerning either as I can't see a clear relationship yet with the input serial bytes or the `i`s. As those two are the only user-input derived data, those are the only ones I care about for now.

What I learned from this part though is that there are new players in town. Basically, three blobs of 16 bytes, respectively called `mask`, `mask3` and `shiftedmask`, get initialized with values derived from `rand()`. At first, it sure is a bit confusing to see pseudo-randomized values getting involved but we can assume those operations will get canceled out by some others. It wouldn't make sense to have some crypto looking algorithm producing non deterministic results. The PRNG is seeded with `time(NULL)`.

```C
do
{
  v16 = v15 + 4;
  do
  {
    rd = rand();
    v18 = (unsigned __int8)(((unsigned __int64)rd >> 56) + rd) - ((unsigned int)(rd >> 31) >> 24);
    mask[v15] = v18;
    mask3[v15] = v18;
    shiftedmask[v15++] = v18;
  }
  while ( v15 != v16 );
}
while ( v15 != 16 );
```

After this, there are a bunch of other operations that we don't care about. Really, you can see those as black boxes that generate deterministic outputs. It means we will be able to conveniently dump the generated values whenever needed. For what it's worth, it basically mixes a bunch of values inside `mask3`.

```C
shiftrows((unsigned __int8 (*)[4])shiftedmask);
shiftrows((unsigned __int8 (*)[4])mask3);
v19 = mul3[(unsigned __int8)byte_D03774] ^ mul2[mask3[0]] ^ byte_D03778 ^ byte_D0377C;
v20 = mul3[(unsigned __int8)byte_D0377C] ^ mul2[(unsigned __int8)byte_D03778] ^ byte_D03774 ^ mask3[0];
v21 = mul3[mask3[0]] ^ mul2[(unsigned __int8)byte_D0377C] ^ byte_D03778 ^ byte_D03774;
byte_D03774 = mul3[(unsigned __int8)byte_D03778] ^ mul2[(unsigned __int8)byte_D03774] ^ mask3[0] ^ byte_D0377C;
mask3[0] = v19;
byte_D03778 = v20;
byte_D0377C = v21;
v22 = mul3[(unsigned __int8)byte_D0377D] ^ mul2[(unsigned __int8)byte_D03779] ^ mask3[1] ^ byte_D03775;
v23 = mul3[(unsigned __int8)byte_D03775] ^ mul2[mask3[1]] ^ byte_D03779 ^ byte_D0377D;
v24 = mul3[mask3[1]] ^ mul2[(unsigned __int8)byte_D0377D] ^ byte_D03779 ^ byte_D03775;
byte_D03775 = mul3[(unsigned __int8)byte_D03779] ^ mul2[(unsigned __int8)byte_D03775] ^ mask3[1] ^ byte_D0377D;
mask3[1] = v23;
byte_D03779 = v22;
byte_D0377D = v24;
v25 = mul3[(unsigned __int8)byte_D0377E] ^ mul2[(unsigned __int8)byte_D0377A] ^ byte_D03776 ^ mask3[2];
v26 = mul3[mask3[2]] ^ mul2[(unsigned __int8)byte_D0377E] ^ byte_D0377A ^ byte_D03776;
v27 = mul3[(unsigned __int8)byte_D03776] ^ mul2[mask3[2]] ^ byte_D0377E ^ byte_D0377A;
byte_D03776 = mul3[(unsigned __int8)byte_D0377A] ^ mul2[(unsigned __int8)byte_D03776] ^ byte_D0377E ^ mask3[2];
byte_D0377A = v25;
byte_D0377E = v26;
mask3[2] = v27;
v28 = mul3[(unsigned __int8)byte_D03777] ^ mul2[mask3[3]] ^ byte_D0377F ^ byte_D0377B;
v29 = mul3[(unsigned __int8)byte_D0377F] ^ mul2[(unsigned __int8)byte_D0377B] ^ byte_D03777 ^ mask3[3];
v30 = mul3[mask3[3]] ^ mul2[(unsigned __int8)byte_D0377F] ^ byte_D0377B ^ byte_D03777;
byte_D03777 = mul3[(unsigned __int8)byte_D0377B] ^ mul2[(unsigned __int8)byte_D03777] ^ byte_D0377F ^ mask3[3];
mask3[3] = v28;
byte_D0377B = v29;
byte_D0377F = v30;
*(__m128i *)mask3 = _mm_xor_si128(_mm_load_si128((const __m128i *)mask), *(__m128i *)mask3);
```

`mul3` and `mul2` are basically arrays that have been constructed such as `mul2[idx] = idx * 2` and `mul3[idx] = idx * 3`.

```C
const uint8_t mul2[256] {
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
    0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
    0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e,
    0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
    0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e,
    0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
    0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e,
    0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
    0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e,
    0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
    0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae,
    0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
    0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce,
    0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
    0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
    0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
    0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15,
    0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
    0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35,
    0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
    0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55,
    0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
    0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75,
    0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
    0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95,
    0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
    0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5,
    0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
    0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5,
    0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
    0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5,
    0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5,
};
```

One thing of interest - maybe - is that there is a small anti-debug in there. The file is opened and read using one of `std::vector`'s constructor that takes an `std::ifstreambuf_iterator` as input. Some sort of sum of control is generated and will be used later in the `schedule` routine. What this means is that if you were about to patch the binary, the algorithm would end up generating *wrong* values. Again, this is barely an inconvenience as we can just dump it out and carry on with our lives.

```C
std::basic_ifstream<char,std::char_traits<char>>::basic_ifstream(&v63, *v3, 4LL);
std::vector<unsigned char,std::allocator<unsigned char>>::vector<std::istreambuf_iterator<char,std::char_traits<char>>,void>(
  &v46,
  *(_QWORD **)((char *)&v64 + *(_QWORD *)(v63 - 24)),
  -1,
  0LL,
  -1);
v31 = v46;
if ( (signed int)v47 - (signed int)v46 > 0 )
{
  v32 = 0LL;
  v33 = (unsigned int)(v47 - (_DWORD)v46 - 1) + 1LL;
  do
  {
    v34 = v32 & 0xF;
    v35 = v31[v32++] ^ *((_BYTE *)&crc + v34);
    *((_BYTE *)&crc + v34) = v35;
  }
  while ( v32 != v33 );
}
```

## Generation

At this point, the 15 `i`'s from above are used to initialize what I called `s0`, `s1`, ..., `s14`. Again, it is 15 blobs of 16 bytes each. They are passed to the `schedule` function that will perform a lot of arithmetic operations on the array of `s`'s. Again, no need to understand `schedule` just yet; as far as we are concerned it is a black box that takes `s`'s in input and gives us back different `s`'s in output, period.

Each of those 16 bytes (xmmwords) (`s0`, ..., `s14`) are XOR'ed together, and if the resulting *xmmword* obeys a bunch of constraints then you get the good boy message.

Those constraints look like this:

```C
h1 = mxor.m128i_u8[0] | ((mxor.m128i_u8[4] | ((mxor.m128i_u8[8] | ((mxor.m128i_u8[12] | ((mxor.m128i_u8[1] | ((mxor.m128i_u8[5] | ((mxor.m128i_u8[9] | ((unsigned __int64)mxor.m128i_u8[13] << 8)) << 8)) << 8)) << 8)) << 8)) << 8)) << 8);
h2 = mxor.m128i_u8[2] | ((mxor.m128i_u8[6] | ((mxor.m128i_u8[10] | ((mxor.m128i_u8[14] | ((mxor.m128i_u8[3] | ((mxor.m128i_u8[7] | ((mxor.m128i_u8[11] | ((unsigned __int64)mxor.m128i_u8[15] << 8)) << 8)) << 8)) << 8)) << 8)) << 8)) << 8);
if ( BYTE6(h2) == 'i'
  && BYTE5(h2) == '7'
  && BYTE4(h2) == '\x13'
  && (mxor.m128i_u8[2] | ((mxor.m128i_u8[6] | ((mxor.m128i_u8[10] | ((mxor.m128i_u8[14] | ((mxor.m128i_u8[3] | ((mxor.m128i_u8[7] | ((mxor.m128i_u8[11] | ((unsigned int)mxor.m128i_u8[15] << 8)) << 8)) << 8)) << 8)) << 8)) << 8)) << 8)) >> 24 == 66
  && (unsigned __int8)((mxor.m128i_u8[2] | ((mxor.m128i_u8[6] | ((mxor.m128i_u8[10] | ((mxor.m128i_u8[14] | ((mxor.m128i_u8[3] | ((mxor.m128i_u8[7] | ((mxor.m128i_u8[11] | ((unsigned int)mxor.m128i_u8[15] << 8)) << 8)) << 8)) << 8)) << 8)) << 8)) << 8)) >> 16) == 105
  && BYTE1(h2) == 55
  && mxor.m128i_i8[2] == 19
  && HIBYTE(h1) == 66
  && BYTE6(h1) == 105
  && BYTE5(h1) == 55
  && BYTE4(h1) == 19
  && (mxor.m128i_u8[0] | ((mxor.m128i_u8[4] | ((mxor.m128i_u8[8] | ((mxor.m128i_u8[12] | ((mxor.m128i_u8[1] | ((mxor.m128i_u8[5] | ((mxor.m128i_u8[9] | ((unsigned int)mxor.m128i_u8[13] << 8)) << 8)) << 8)) << 8)) << 8)) << 8)) << 8)) >> 24 == 66
  && (unsigned __int8)((mxor.m128i_u8[0] | ((mxor.m128i_u8[4] | ((mxor.m128i_u8[8] | ((mxor.m128i_u8[12] | ((mxor.m128i_u8[1] | ((mxor.m128i_u8[5] | ((mxor.m128i_u8[9] | ((unsigned int)mxor.m128i_u8[13] << 8)) << 8)) << 8)) << 8)) << 8)) << 8)) << 8)) >> 16) == 105
  && BYTE1(h1) == 55
  && mxor.m128i_i8[0] == 19
  && h2 >> 56 == 66 )
{
  puts("**** Login Successful ****");
  v42 = 0;
}
else
{
  puts("**** Login Failed ****");
  v42 = 1;
}
```

This garbage simply translates to `win = (mxor == 0x42424242696969693737373713131313ULL)` :).

# Zooming in

It is now a good time to zoom in and get our hands dirty a little. We sort of know what we need to achieve, but we need to know how to get there now. We know we have some dumping to do: `mask`, `mask3`, `shiftedmask`, `crc`, `sbx`, `mul2` and `mul3`. Easy. Mechanical.

The most important part though is to understand a bit more `schedule`. You can consider it as the heart of the challenge. So let's do that.

## schedule

At first sight, the function doesn't look too bad which is always nice. The first part of the function is randomly selecting one of the `s`'s variable (the variable `i` is used to index into the `states` array where all the `s`'s are).

```C
for(i = rand() % 15; scheduling[i] == 40; i = rand() % 15);
nround = scheduling[i];
```

The switch case that follows applies one type of transformation (arithmetic ones) on the chosen `s` variable. In order to track the number of *rounds* already applied to each `s`'s variables, an array called `scheduling` is used. The algorithm stops when forty rounds has been applied to every `s`'s. It's also worth to point out that there's a small anti-debugging here; a timer is started at the beginning (`t1`) of the round and stopped at the end (`t2`). If any abnormal delay between `t1` and `t2` is discovered the later computations will produce *wrong* results.

We can observe 6 different type of operations in the switch case. Some of them look very easily invertible and some others would need some more work. But at this point, it reminds me a lot of this AES whitebox I analyzed back in [2013](https://github.com/0vercl0k/articles/blob/master/AES%20Whitebox%20Unboxing%20No%20Such%20Problem.pdf). This one doesn't have any obfuscation which makes it much easier to deal with. What I did at the time was pretty simple: divide and conquer. I broke down each round in four pieces. Each of those *quarter* round worked as a black box function that took 4 bytes of input and generated 4 bytes of output (as a result each round would generate 16 bytes/128bits). I needed to find the 4 bytes of input that would give me the 4 bytes of output I wanted. Solving those quarters could be done simultaneously and starting from the desired output you could go walk back from round `N` to round `N-1`. That was basically my plan for `ctf2`.

At this point I already had ripped out the `schedule` function in my own program. I cleaned-up the code and made sure it produced the same results that the program itself (always fun to debug). In other words, I was ready to go forward with the analysis of all the arithmetic boxes.

### case 0: encoding
This case is as simple as it gets as you can see below:

```C
case 0:
  s0[i] = _mm_xor_si128(_mm_load_si128(&s0[i]), *(__m128i *)mask);
  break;
```

As a result, inverting it is a simple XOR operation:

```C
void reverse_0(Slot_t &Output, Slot_t &Input) {
    Input = _mm_xor_si128(_mm_load_si128(&Output), mask);
}
```

### case 1, 5, 9, 13, 17, 21, 25, 29, 33, 37: SubBytes
This case can look a bit more intimidating compared to the previous one (lol). Here is how it looks like once I have cleaned and prettified it a bit:

```C
case 1:
case 5:
case 9:
case 13:
case 17:
case 21:
case 25:
case 29:
case 33:
case 37: {
    v54 = nround >> 2;
    v55 = Slot->m128i_u8[0];
    v77.m128i_u64[0] = mask.m128i_u8[0];
    v56 = v54;
    v54 <<= 20;
    v79 = mask.m128i_u8[1];
    v81 = mask.m128i_u8[2];
    v57 = &sboxes[256 * (v55 + (v56 << 12))];
    v58 = Slot->m128i_u8[1];
    v80 = &sboxes[256 * v58 + v54];
    v60 = Slot->m128i_u8[2];
    v61 = &sboxes[256 * v60 + v54];
    v62 = Slot->m128i_u8[3];
    v83 = &sboxes[256 * v62 + v54];
    v64 = Slot->m128i_u8[4];
    v84 = &sboxes[256 * v64 + v54];
    v65 = Slot->m128i_u8[6];
    v85 = &sboxes[256 * uint64_t(Slot->m128i_u8[5]) + v54];
    v66 = &sboxes[256 * v65 + v54];
    v67 = Slot->m128i_u8[7];
    v68 = &sboxes[256 * v67 + v54];
    v69 = Slot->m128i_u8[8];
    v88 = mask.m128i_u8[8];
    v89 = &sboxes[256 * v69 + v54];
    v90 = mask.m128i_u8[9];
    v70 = v54 + (uint64_t(Slot->m128i_u8[9]) << 8);
    v92 = mask.m128i_u8[10];
    v91 = &sboxes[v70];
    v71 = Slot->m128i_u8[10];
    v94 = mask.m128i_u8[11];
    v96 = mask.m128i_u8[12];
    v93 = &sboxes[256 * v71 + v54];
    v72 = Slot->m128i_u8[11];
    v98 = mask.m128i_u8[13];
    v95 = &sboxes[256 * v72 + v54];
    v73 = Slot->m128i_u8[12];
    v100 = mask.m128i_u8[14];
    v97 = &sboxes[256 * v73 + v54];
    v99 = &sboxes[256 * uint64_t(Slot->m128i_u8[13]) + v54];
    v101 = &sboxes[256 * uint64_t(Slot->m128i_u8[14]) + v54];
    Slot->m128i_u8[0] = v57[mask.m128i_u8[0]];
    Slot->m128i_u8[1] = v80[mask.m128i_u8[1] + 0x10000];
    Slot->m128i_u8[2] = v61[mask.m128i_u8[2] + 0x20000];
    Slot->m128i_u8[3] = v83[mask.m128i_u8[3] + 196608];
    Slot->m128i_u8[4] = v84[mask.m128i_u8[4] + 0x40000];
    Slot->m128i_u8[5] = v85[mask.m128i_u8[5] + 327680];
    Slot->m128i_u8[6] = v66[mask.m128i_u8[6] + 393216];
    Slot->m128i_u8[7] = v68[mask.m128i_u8[7] + 458752];
    Slot->m128i_u8[8] = v89[mask.m128i_u8[8] + 0x80000];
    Slot->m128i_u8[9] = v91[mask.m128i_u8[9] + 589824];
    Slot->m128i_u8[10] = v93[mask.m128i_u8[10] + 655360];
    Slot->m128i_u8[11] = v95[mask.m128i_u8[11] + 720896];
    Slot->m128i_u8[12] = v97[mask.m128i_u8[12] + 786432];
    Slot->m128i_u8[13] = v99[mask.m128i_u8[13] + 851968];
    Slot->m128i_u8[14] = v101[mask.m128i_u8[14] + 917504];
    Slot->m128i_u8[15] = sboxes[256 * uint64_t(Slot->m128i_u8[15]) + 983040 + v54 + mask.m128i_u8[15]];
    *Slot = _mm_xor_si128(*Slot, crc);
    break;
}
```

The thing I always focus on is: the relationship between the input and output bytes. Remember that each round works as a function that takes a 16 bytes blob in input (a `Slot_t` in my code) and returns another 16 bytes blob as output. As we are interested to write a function that can find an input that generates a specific output it is very important to identify how the output is built and what input bytes are used to build it.

Let's have a closer look at how the first byte of the output is generated. We start from the end of the function and we follow back the references until we encounter a byte from the input state. In this case we trace back where `v57` is coming from, and then `v55` and `v56`. `v55` is the first byte of the input state, great. `v56` is a 
a number encoding the number of the round. We don't necessarily care about it as of now, but it's good to realize that the number of the round is a parameter of this function; and not exclusively the inputs bytes. OK so we know that the first byte of the output is built via the first byte of the input, easy. Simpler than I first expected when looking at the Hex-Rays' output to be honest. But I'll take simple :).

If you repeat the above steps for every bytes you basically realize that each bytes of the output is dependent on one single byte of input. They are all independent one from another which is even nicer. What this means is that we can very easily brute-force an input value to generate a specific output value. That's great because it is ... very cheap to compute; so cheap that we don't even bother and we move on to the next case.

In theory we could even parallelize the below but it's probably not worth doing as already fast.

```C
void reverse_37(const uint32_t nround, Slot_t &Output, Slot_t &Input) {
    uint8_t is[16];
    for (uint32_t i = 0; i < 16; ++i) {
        for (uint32_t c = 0; c < 0x100; ++c) {
            Input.m128i_u8[i] = c;
            round(nround, &Input);
            if (Input.m128i_u8[i] == Output.m128i_u8[i]) {
                is[i] = c;
                break;
            }
        }
    }
    memcpy(Input.m128i_u8, is, 16);
}
``` 

Funny enough, if you patched the challenge binary this is yet another spot where things would go wrong. The `crc` value is used at the end of the function to XOR the output state and would pollute your results here, sneaky :). 

### case 2, 6, 10, 14, 18, 22, 26, 30, 34, 38: ShiftRows
Not bad, we already figured out two cases out of the six. This case doesn't look too bad either, it is pretty short and writing an inverse looks easy enough:

```C
case 2:
case 6:
case 10:
case 14:
case 18:
case 22:
case 26:
case 30:
case 34:
case 38: {
    v42 = Slot->m128i_u8[6];
    v43 = Slot->m128i_u8[4];
    v44 = Slot->m128i_u8[5];
    Slot->m128i_u8[6] = Slot->m128i_u8[7];
    Slot->m128i_u8[5] = v42;
    v45 = Slot->m128i_u8[8];
    v46 = Slot->m128i_u8[11];
    Slot->m128i_u8[4] = v44;
    Slot->m128i_u8[7] = v43;
    v47 = Slot->m128i_u8[10];
    v48 = Slot->m128i_u8[9];
    Slot->m128i_u8[10] = v45;
    Slot->m128i_u8[9] = v46;
    v49 = Slot->m128i_u8[13];
    v50 = Slot->m128i_u8[12];
    Slot->m128i_u8[8] = v47;
    Slot->m128i_u8[11] = v48;
    v51 = Slot->m128i_u8[15];
    v52 = Slot->m128i_u8[14];
    Slot->m128i_u8[13] = v50;
    Slot->m128i_u8[14] = v49;
    Slot->m128i_u8[12] = v51;
    Slot->m128i_u8[15] = v52;
    break;
}
```

Clearly just by quickly looking at this function you understand that it is some sort of shuffling operation. For whatever reason, this is the type of brain-gymnastic that I am not good at. The trick I usually use is to give it an input that looks like this: `\x00\x01\x02\x03...` and observe the result.

```C
void test_reverse38() {
    const uint8_t Input[16] {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    Slot_t InputSlot;
    memcpy(&InputSlot.m128i_u8, Input, 16);
    round(38, &InputSlot);
    hexdump(stdout, &InputSlot.m128i_u8, 16);
}
```

This is what we get if we apply the above trick:

```text
0000:   00 01 02 03 05 06 07 04   0A 0B 08 09 0F 0C 0D 0E    ................
```

From here, it's much easier (for me at least) to figure out the effect of the shuffling. For example, we already know we have nothing to do with the first four bytes as they haven't been shuffled. We know we need to take `Output[7]` and put it inside `Input[4]`, `Output[4]` in `Input[5]`, so on and so forth. After a bit of mental gymnastics I end-up with this routine:

```C
void reverse_38(Slot_t &Output, Slot_t &Input) {
    uint8_t s4 = Output.m128i_u8[4];
    Output.m128i_u8[4] = Output.m128i_u8[7];
    uint8_t s5 = Output.m128i_u8[5];
    Output.m128i_u8[5] = s4;
    uint8_t s6 = Output.m128i_u8[6];
    Output.m128i_u8[6] = s5;
    uint8_t s7 = Output.m128i_u8[7];
    Output.m128i_u8[7] = s6;
    uint8_t s8 = Output.m128i_u8[8];
    Output.m128i_u8[8] = Output.m128i_u8[10];
    uint8_t s9 = Output.m128i_u8[9];
    Output.m128i_u8[9] = Output.m128i_u8[11];
    Output.m128i_u8[10] = s8;
    Output.m128i_u8[11] = s9;
    uint8_t s12 = Output.m128i_u8[12];
    Output.m128i_u8[12] = Output.m128i_u8[13];
    uint8_t s13 = Output.m128i_u8[13];
    Output.m128i_u8[13] = Output.m128i_u8[14];
    Output.m128i_u8[14] = Output.m128i_u8[15];
    Output.m128i_u8[15] = s12;
    memcpy(Input.m128i_u8, Output.m128i_u8, 16);
}
```

Next one!

### case 3, 7, 11, 15, 19, 23, 27, 31, 35: MixColumns

This case is the most annoying one basically. At first sight, it looks very similar as the `case 1` we analyzed earlier, but ... not quite. 

```C
case 3:
case 7:
case 11:
case 15:
case 19:
case 23:
case 27:
case 31:
case 35: {
    v7 = Slot->m128i_u8[0];
    v8 = Slot->m128i_u8[4];
    v9 = Slot->m128i_u8[1];
    v10 = Slot->m128i_u8[5];
    v11 = Slot->m128i_u8[14] ^ Slot->m128i_u8[10];
    v12 = mul3[v8] ^ mul2[v7] ^ Slot->m128i_u8[12] ^ Slot->m128i_u8[8];
    v81 = Slot->m128i_u8[3];
    uint8_t v78x = v12;
    uint8_t v79x = mul3[v10] ^ mul2[v9] ^ Slot->m128i_u8[13] ^ Slot->m128i_u8[9];
    v77.m128i_u64[0] = Slot->m128i_u8[2];
    v13 = mul2[v77.m128i_u64[0]] ^ v11;
    v14 = Slot->m128i_u8[6];
    uint8_t v80x = mul3[v14] ^ v13;
    v15 = Slot->m128i_u8[7];
    uint8_t v82x = mul3[v15] ^ mul2[v81] ^ Slot->m128i_u8[15] ^ Slot->m128i_u8[11];
    v16 = mul2[v8] ^ Slot->m128i_u8[12] ^ Slot->m128i_u8[0];
    v17 = Slot->m128i_u8[8];
    uint8_t v83x = mul3[v17] ^ v16;
    v18 = mul2[v10] ^ Slot->m128i_u8[13] ^ Slot->m128i_u8[1];
    v19 = Slot->m128i_u8[9];
    v20 = Slot->m128i_u8[14] ^ Slot->m128i_u8[2];
    uint8_t v84x = mul3[v19] ^ v18;
    v21 = mul2[v14] ^ v20;
    v22 = Slot->m128i_u8[10];
    v23 = Slot->m128i_u8[15] ^ Slot->m128i_u8[3];
    uint8_t v85x = mul3[v22] ^ v21;
    v24 = mul2[v15] ^ v23;
    v25 = Slot->m128i_u8[11];
    v26 = Slot->m128i_u8[4] ^ Slot->m128i_u8[0];
    uint8_t v86x = mul3[v25] ^ v24;
    v27 = mul2[v17] ^ v26;
    v28 = Slot->m128i_u8[12];
    v29 = Slot->m128i_u8[5] ^ Slot->m128i_u8[1];
    uint8_t v87x = mul3[v28] ^ v27;
    v30 = mul2[v19] ^ v29;
    v31 = Slot->m128i_u8[13];
    v32 = Slot->m128i_u8[6] ^ Slot->m128i_u8[2];
    uint8_t v88x = mul3[v31] ^ v30;
    v33 = mul2[v22] ^ v32;
    v34 = Slot->m128i_u8[14];
    v35 = Slot->m128i_u8[7] ^ Slot->m128i_u8[3];
    uint8_t v89x = mul3[v34] ^ v33;
    v36 = mul2[v25] ^ v35;
    v37 = Slot->m128i_u8[15];
    v38 = Slot->m128i_u8[8] ^ Slot->m128i_u8[4];
    uint8_t v90x = mul3[v37] ^ v36;
    uint8_t v7x = mul2[v28] ^ v38 ^ mul3[v7];
    v9 = mul2[v31] ^ Slot->m128i_u8[9] ^ Slot->m128i_u8[5] ^ mul3[v9];
    v39 = mul3[v77.m128i_u64[0]] ^ mul2[v34] ^ Slot->m128i_u8[10] ^ Slot->m128i_u8[6];
    v40 = mul3[v81] ^ Slot->m128i_u8[11] ^ Slot->m128i_u8[7] ^ mul2[v37];
    Slot->m128i_u8[0] = v78x;
    Slot->m128i_u8[1] = v79x;
    Slot->m128i_u8[2] = v80x;
    Slot->m128i_u8[3] = v82x;
    Slot->m128i_u8[4] = v83x;
    Slot->m128i_u8[5] = v84x;
    Slot->m128i_u8[6] = v85x;
    Slot->m128i_u8[7] = v86x;
    Slot->m128i_u8[8] = v87x;
    Slot->m128i_u8[9] = v88x;
    Slot->m128i_u8[10] = v89x;
    Slot->m128i_u8[11] = v90x;
    Slot->m128i_u8[12] = v7x;
    Slot->m128i_u8[13] = uint8_t(v9);
    Slot->m128i_u8[14] = v39;
    Slot->m128i_u8[15] = v40;
    break;
}
```

This time if you take a closer look, we notice that each group of four bytes of output depends of four bytes of input. And every byte of those four bytes of output depend on those four input bytes.

This means that you cannot brute force byte by byte like earlier. You have to brute force four bytes... which is much more costly compared to what we've seen above. The only thing going for us is that we can brute force them in parallel as they are independent from each other. A thread for each should do the work.

At this stage I already wasted a bunch of time on various bugs or stupid things; so I decided to write this very simple naive brute force function (it's not pretty nor fast... but I've made peace with it at this point):

```C
void reverse_35(Slot_t &Output, Slot_t &Input) {
    uint8_t final_result[16];
    std::thread t0([Input, Output, &final_result]() mutable {
        for (uint64_t a = 0; a < 0x100; ++a) {
            for (uint64_t b = 0; b < 0x100; ++b) {
                for (uint64_t c = 0; c < 0x100; ++c) {
                    for (uint64_t d = 0; d < 0x100; ++d) {
                        Input.m128i_u8[0] = uint8_t(a);
                        Input.m128i_u8[4] = uint8_t(b);
                        Input.m128i_u8[8] = uint8_t(c);
                        Input.m128i_u8[12] = uint8_t(d);
                        round(35, &Input);
                        if (Input.m128i_u8[0] == Output.m128i_u8[0] && Input.m128i_u8[4] == Output.m128i_u8[4] &&
                            Input.m128i_u8[8] == Output.m128i_u8[8] && Input.m128i_u8[12] == Output.m128i_u8[12]) {

                            final_result[0] = uint8_t(a);
                            final_result[4] = uint8_t(b);
                            final_result[8] = uint8_t(c);
                            final_result[12] = uint8_t(d);
                            return;
                        }
                    }
                }
            }
        }
    });
    std::thread t1([Input, Output, &final_result]() mutable {
        for (uint64_t a = 0; a < 0x100; ++a) {
            for (uint64_t b = 0; b < 0x100; ++b) {
                for (uint64_t c = 0; c < 0x100; ++c) {
                    for (uint64_t d = 0; d < 0x100; ++d) {
                        Input.m128i_u8[1] = uint8_t(a);
                        Input.m128i_u8[5] = uint8_t(b);
                        Input.m128i_u8[9] = uint8_t(c);
                        Input.m128i_u8[13] = uint8_t(d);
                        round(35, &Input);
                        if (Input.m128i_u8[1] == Output.m128i_u8[1] && Input.m128i_u8[5] == Output.m128i_u8[5] &&
                            Input.m128i_u8[9] == Output.m128i_u8[9] && Input.m128i_u8[13] == Output.m128i_u8[13]) {

                            final_result[1] = uint8_t(a);
                            final_result[5] = uint8_t(b);
                            final_result[9] = uint8_t(c);
                            final_result[13] = uint8_t(d);
                            return;
                        }
                    }
                }
            }
        }
    });
    std::thread t2([Input, Output, &final_result]() mutable {
        for (uint64_t a = 0; a < 0x100; ++a) {
            for (uint64_t b = 0; b < 0x100; ++b) {
                for (uint64_t c = 0; c < 0x100; ++c) {
                    for (uint64_t d = 0; d < 0x100; ++d) {
                        Input.m128i_u8[2] = uint8_t(a);
                        Input.m128i_u8[6] = uint8_t(b);
                        Input.m128i_u8[10] = uint8_t(c);
                        Input.m128i_u8[14] = uint8_t(d);
                        round(35, &Input);
                        if (Input.m128i_u8[2] == Output.m128i_u8[2] && Input.m128i_u8[6] == Output.m128i_u8[6] &&
                            Input.m128i_u8[10] == Output.m128i_u8[10] && Input.m128i_u8[14] == Output.m128i_u8[14]) {

                            final_result[2] = uint8_t(a);
                            final_result[6] = uint8_t(b);
                            final_result[10] = uint8_t(c);
                            final_result[14] = uint8_t(d);
                            return;
                        }
                    }
                }
            }
        }
    });
    std::thread t3([Input, Output, &final_result]() mutable {
        for (uint64_t a = 0; a < 0x100; ++a) {
            for (uint64_t b = 0; b < 0x100; ++b) {
                for (uint64_t c = 0; c < 0x100; ++c) {
                    for (uint64_t d = 0; d < 0x100; ++d) {
                        Input.m128i_u8[3] = uint8_t(a);
                        Input.m128i_u8[7] = uint8_t(b);
                        Input.m128i_u8[11] = uint8_t(c);
                        Input.m128i_u8[15] = uint8_t(d);
                        round(35, &Input);
                        if (Input.m128i_u8[3] == Output.m128i_u8[3] && Input.m128i_u8[7] == Output.m128i_u8[7] &&
                            Input.m128i_u8[11] == Output.m128i_u8[11] && Input.m128i_u8[15] == Output.m128i_u8[15]) {

                            final_result[3] = uint8_t(a);
                            final_result[7] = uint8_t(b);
                            final_result[11] = uint8_t(c);
                            final_result[15] = uint8_t(d);
                            return;
                        }
                    }
                }
            }
        }
    });
   
    t0.join();
    t1.join();
    t2.join();
    t3.join();
    memcpy(Input.m128i_u8, final_result, 16);
    return;
}
```

Each thread recovers four bytes and the results are aggregated in `final_result`, easy. 

### case 4, 8, 12, 16, 20, 24, 28, 32, 36: AddRoundKey
This case is another trivial one where a simple XOR does the job to invert the operation:

```C
case 4:
case 8:
case 12:
case 16:
case 20:
case 24:
case 28:
case 32:
case 36: {
    *Slot = _mm_xor_si128(_mm_load_si128(Slot), mask3);
    break;
}
```

Note that `mask3` is one of the array that gets modified when you introduce an abnormal delay in a round; like if you're debugging for example. Yet another spot where wrong results could be produced :).

```C
void reverse_36(Slot_t &Output, Slot_t &Input) {
    Input = _mm_xor_si128(_mm_load_si128(&Output), mask3);
}
```

### case 39: decoding

And finally our last case is another very simple one:

```C
case 39: {
    *Slot = _mm_xor_si128(_mm_load_si128(Slot), shiftedmask);
    break;
}
```

Inverted with the below:

```C
void reverse_39(Slot_t &Output, Slot_t &Input) {
    Input = _mm_xor_si128(_mm_load_si128(&Output), shiftedmask);
}
```

## unround

At this stage we have all the small blocks we need to find an input state that generates a specific output state. We simply combine all the `reverse_` routines we wrote into a function that basically is the invert of `schedule`. We also create a utility function that applies forty `unround` to a state in order to fully invert it: from bottom to top.

```C
void recover_state(Slot_t &Output, Slot_t &Input) {
    for (int32_t i = 39; i > -1; --i) {
        unround(i, Output, Input);
        memcpy(Output.m128i_u8, Input.m128i_u8, 16);
    }
}
```

Once we have that available we can use it in order to do try to - let's say - find the input bytes that generates the following output `'doar-e.github.io'.encode('hex')`.

```C
void recover_doare() {
    const uint8_t WantedOutputBytes[16] {
        // In [17]: ', '.join('0x%2x' % ord(c) for c in 'doar-e.github.io')
        // Out[17]: '0x64, 0x6f, 0x61, 0x72, 0x2d, 0x65, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x69, 0x6f'
        0x64, 0x6f, 0x61, 0x72, 0x2d, 0x65, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x69, 0x6f
    };
    Slot_t WantedOutput, Input;
    memcpy(WantedOutput.m128i_u8, WantedOutputBytes, 16);
    recover_state(WantedOutput, Input);
    hexdump(stdout, Input.m128i_u8, 16);
}
```

This gives us back the following (it takes about 7 min on my machine VS 13 min without the multi threaded version of `reverse_35`):

```C
0000:   0D CC 49 C2 F8 E1 6A 78   1D 57 26 F7 45 AB 3E 13    ..I...jx.W&.E.>.
```

To ensure that it works properly we can fire up *gdb* and inject this state right before the scheduling phase like in the below:

```text
gef➤  pie breakpoint *0x114c
gef➤  pie run
[...]
gef➤  eb &states 0x0D 0xCC 0x49 0xC2 0xF8 0xE1 0x6A 0x78 0x1D 0x57 0x26 0xF7 0x45 0xAB 0x3E 0x13
gef➤  x/16bx &states
0x555556257660 <states>:        0x0d    0xcc    0x49    0xc2    0xf8    0xe1    0x6a    0x78
0x555556257668 <states+8>:      0x1d    0x57    0x26    0xf7    0x45    0xab    0x3e    0x13
g
gef➤  x/i $rip
=> 0x55555555514c <main+1276>:  call   0x555555555660 <_Z8schedulev>
gef➤  n
gef➤  x/i $rip
=> 0x555555555151 <main+1281>:  movdqa xmm0,XMMWORD PTR [rip+0xd02517]        # 0x555556257670 <states+16>
gef➤  x/16bx &states
0x555556257660 <states>:        0x64    0x6f    0x61    0x72    0x2d    0x65    0x2e    0x67
0x555556257668 <states+8>:      0x69    0x74    0x68    0x75    0x62    0x2e    0x69    0x6f
gef➤  x/1s &states
0x555556257660 <states>:        "doar-e.github.iovطL:2\204\274\006\"A\377+ⴄ\256^\264)\220\024\307\356dO\377a\003Q}\317+\352\064\303I\300\254\256\271\061\306\004\327\033\375\307B\357\375m\027u\024\060\315t\a\034\247\224\027\005\202\021oK\366\267>\373X`?\027\071*\333\301\357\a\260\256\063k}u\232f\212\212\246'\303j\027\201\061@\246\336\304mۡ\bSi\214\034\210D\327.hQ\310\302I,\225zF\263안vطL:2\204\274\006\"A\377+ⴄ\256^\264)\220\024\307\356dO\377a\003Q}\317+\352\064\303I\300\254\256\271\061\306\004\327\033\375\307B\357\375m\027u\024\060\315t\a\034\247\224\027\005\202\021oK\366\267>\373X`?\027\071*\333\301\357\a\260\256\063k}u\232f\212\212\246'\303j\233\004WD\345\037\360\371\350JT\332h\340R\270\223\256\247\356͚C\211\374\327=\022>\222\301\346 \031\313]\272\274=t\302>:\245qZ\363[\223\256\247\356\211͚C=\022\374ג\301\346>"
```

All right, awesome. Sounds like we are done with schedule for now :).

## How do I win now?

From above, we already established that the 15 `s`'s blobs get XOR'ed together and if the result is `0x42424242696969693737373713131313ULL` then it's a win, great. We also know that the input serial is diffused in those 15 blobs. In each blobs, there are all the bytes of the serial input. They are just mixed in differently depending on which blob it is. What this means is that when we give the good serial to the program, we can fully control only one of those blob. And as they are XOR'ed together it's unclear at first sight how we can get the resulting XOR equal to the magic value, strange.

After being stuck a bit on this (and still being mad at myself for it D:), my friend [mongo](https://twitter.com/mongobug) asked me if I **really** took a look at what the 15 blobs look like. Ugh, I guess I kinda did? At this point I fired up my debugger and saw the below fifteen blobs (for the following serial `00112233445566778899AABBCCDDEEFF`):

```text
gef➤  pie breakpoint *0x0000000000001144c
gef➤  pie run
gef➤  x/240bx &states
0x555556257660 <states>:        0x66    0xcc    0x33    0x55    0x88    0xee    0x77    0x00
0x555556257668 <states+8>:      0xdd    0x22    0x99    0x11    0xff    0xbb    0x44    0xaa
0x555556257670 <states+16>:     0xff    0xcc    0x66    0xaa    0x99    0x55    0x22    0x00
0x555556257678 <states+24>:     0x77    0x11    0x88    0xbb    0xdd    0x33    0xee    0x44
0x555556257680 <states+32>:     0xaa    0x33    0xdd    0xcc    0x66    0xee    0x11    0x44
0x555556257688 <states+40>:     0xbb    0x55    0x77    0xff    0x22    0x00    0x88    0x99
0x555556257690 <states+48>:     0xaa    0x55    0x33    0x11    0xbb    0xdd    0x66    0xcc
0x555556257698 <states+56>:     0x22    0xff    0x44    0x88    0xee    0x77    0x99    0x00
0x5555562576a0 <states+64>:     0x00    0x66    0xbb    0x77    0xff    0x55    0x88    0x33
0x5555562576a8 <states+72>:     0x11    0x44    0x99    0x22    0xcc    0xdd    0xaa    0xee
0x5555562576b0 <states+80>:     0x22    0x00    0x33    0xbb    0xcc    0x88    0x44    0xdd
0x5555562576b8 <states+88>:     0x77    0x55    0xaa    0x11    0x66    0xff    0xee    0x99
0x5555562576c0 <states+96>:     0xcc    0xff    0x00    0x44    0xbb    0x66    0xaa    0x11
0x5555562576c8 <states+104>:    0x99    0x55    0xee    0x33    0x22    0x77    0x88    0xdd
0x5555562576d0 <states+112>:    0x00    0x44    0x88    0xcc    0x11    0x55    0x99    0xdd
0x5555562576d8 <states+120>:    0x22    0x66    0xaa    0xee    0x33    0x77    0xbb    0xff
0x5555562576e0 <states+128>:    0x66    0xcc    0x33    0x55    0x88    0xee    0x77    0x00
0x5555562576e8 <states+136>:    0xdd    0x22    0x99    0x11    0xff    0xbb    0x44    0xaa
0x5555562576f0 <states+144>:    0xff    0xcc    0x66    0xaa    0x99    0x55    0x22    0x00
0x5555562576f8 <states+152>:    0x77    0x11    0x88    0xbb    0xdd    0x33    0xee    0x44
0x555556257700 <states+160>:    0xaa    0x33    0xdd    0xcc    0x66    0xee    0x11    0x44
0x555556257708 <states+168>:    0xbb    0x55    0x77    0xff    0x22    0x00    0x88    0x99
0x555556257710 <states+176>:    0xaa    0x55    0x33    0x11    0xbb    0xdd    0x66    0xcc
0x555556257718 <states+184>:    0x22    0xff    0x44    0x88    0xee    0x77    0x99    0x00
0x555556257720 <states+192>:    0x00    0x66    0xbb    0x77    0xff    0x55    0x88    0x33
0x555556257728 <states+200>:    0x11    0x44    0x99    0x22    0xcc    0xdd    0xaa    0xee
0x555556257730 <states+208>:    0x22    0x00    0x33    0xbb    0xcc    0x88    0x44    0xdd
0x555556257738 <states+216>:    0x77    0x55    0xaa    0x11    0x66    0xff    0xee    0x99
0x555556257740 <states+224>:    0xcc    0xff    0x00    0x44    0xbb    0x66    0xaa    0x11
0x555556257748 <states+232>:    0x99    0x55    0xee    0x33    0x22    0x77    0x88    0xdd
```

Do you see it now? If you look closely, you can see that `states[0] = states[8]`, `states[1] = states[9]`, `states[2] = states[10]`, etc. Which means that XORing them together cancel them out.. leaving the one blob in the middle: `states[7]`.

```text
0x5555562576d0 <states+112>:    0x00    0x44    0x88    0xcc    0x11    0x55    0x99    0xdd
0x5555562576d8 <states+120>:    0x22    0x66    0xaa    0xee    0x33    0x77    0xbb    0xff
```

So now we just have to invoke `recover_state` in order to find an input state that generates this output state: `42424242696969693737373713131313`. When we have recovered the sixteen bytes of input we need to study the diffusion algorithm a little to be able to construct an input serial that generates the `states[7]` of our choice (`slot2password`), easy.

```C
void pwn() {
    const uint8_t WantedOutputBytes[16] {
        0x13, 0x13, 0x13, 0x13, 0x37, 0x37, 0x37, 0x37, 0x69, 0x69, 0x69, 0x69, 0x42, 0x42, 0x42, 0x42,
    };
    Slot_t WantedOutput, Input;
    memcpy(WantedOutput.m128i_u8, WantedOutputBytes, 16);
    recover_state(WantedOutput, Input);
    hexdump(stdout, Input.m128i_u8, 16);
    uint8_t Password[16];
    slot2password(Input.m128i_u8, Password);
    for (size_t i = 0; i < 16; ++i) {
        printf("%.2X", Password[i]);
    }
    printf("\n");
}
```

And after running this for a bit of time we get the below output:

```text
c:\work>C:\work\unboxin-ctf2.exe
0000:   0A 0E C2 74 B7 C6 41 70   98 5F 2D D7 2C C9 52 68    ...t..Ap._-.,.Rh
0AB7982C0EC65FC9C2412D527470D768
e min elapsed
```

Mandatory final check now..:

```text
over@bubuntu:~/workz$ ./ctf2 0AB7982C0EC65FC9C2412D527470D768
**** Login Successful ****
```

Job done :-).

## Conclusion

Interestingly, while I was writing up this article, [ledger](https://www.ledger.fr/) posted one describing the puzzles and some of the solutions they have received. You should definitely check it out: [CTF complete – HW bounty still ongoing](https://www.ledger.fr/2018/06/01/ctf-complete-hw-bounty-still-ongoing-2-337-btc/). The other interesting thing is, as usual, there are many ways leading to victory.

What's fascinating about it, is that in this specific case, studying the cryptography closer have allowed some people to directly extract the AES key. At what point writing a solution becomes trivial: decrypt a blob with AES and the extracted key. No need for any reimplementing any of the program's logic. That's very cool! But there's been an even richer spectrum of solutions: fault injections, side channel attacks, reverse-engineering, etc. That's also why I would definitely recommend to go and read other people solutions :).

In any case, I've uploaded my solution file [unboxin-ctf2.cc](https://github.com/0vercl0k/stuffz/blob/master/ledgerctf2018/ctf2/unboxin-ctf2.cc) on my [github](https://github.com/0vercl0k/) as usual, enjoy!