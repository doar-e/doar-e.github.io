Title: Building a new snapshot fuzzer & fuzzing IDA
Date: 2021-07-15 08:00
Tags: IDA, bug-bounty, snapshot fuzzing, kvm, winhv, whv, bochs, fuzzing, bochscpu
Authors: Axel "0vercl0k" Souchet

# Introduction

It is January 2020 and it is this time of the year where I try to set goals for myself. I had just come back from spending Christmas with my family in France and felt fairly recharged. It always is an exciting time for me to think and plan for the year ahead; who knows maybe it'll be the year where I get good at computers I thought (spoiler alert: it wasn't).

One thing I had in the back of my mind was to develop my own custom fuzzing tooling. It was the perfect occasion to play with technologies like [Windows Hypervisor platform APIs](https://docs.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform), [KVM APIs](https://www.kernel.org/doc/html/latest/virt/kvm/api.html) but also try out what recent versions of C++ had in store. After talking with [yrp604](https://twitter.com/yrp604), he convinced me to write a tool that could be used to fuzz any Windows targets, user or kernel, application or service, kernel or drivers. He had done some work in this area so he could follow me along and help me out when I ran into problems.

Great, the plan was to develop this Windows snapshot-based fuzzer running the target code into some kind of environment like a VM or an emulator. It would allow the user to instrument the target the way they wanted via breakpoints and would provide basic features that you expect from a modern fuzzer: code coverage, crash detection, general mutator, cross-platform support, fast restore, etc.

Writing a tool is cool but writing a useful tool is even cooler. That's why I needed to come up with a target I could try the fuzzer against while developing it. I  thought that [IDA](https://hex-rays.com/IDA-pro/) would make a good target for several reasons:

1. It is a complex Windows user-mode application,
1. It parses a bunch of binary files,
1. The application is heavy and is slow to start. The snapshot approach could help fuzz it faster than traditionally,
1. It has a [bug bounty](https://hex-rays.com/bugbounty/).

In this blog post, I will walk you through the birth of [what the fuzz](https://github.com/0vercl0k/wtf/), its history, and my overall journey from zero to accomplishing my initial goals. For those that want the results before reading, you can find my findings in this Github repository: [fuzzing-ida75](https://github.com/0vercl0k/fuzzing-ida75).

There is also an excellent blog post that my good friend [Markus](https://twitter.com/gaasedelen) authored on [RET2 Systems](https://twitter.com/ret2systems)' blog documenting how he used wtf to find exploitable memory corruption in a triple-A game: [Fuzzing Modern UDP Game Protocols With Snapshot-based Fuzzers](https://blog.ret2.io/2021/07/21/wtf-snapshot-fuzzing/).

[TOC]

# Architecture

At this point I had a pretty good idea of what the final product should look like and how a user would use wtf:

1. The user finds a spot in the target that is close to consuming attacker-controlled data. The Windows kernel debugger is used to break at this location and put the target into the wanted state. When done, the user generates a kernel-crash dump and extracts the CPU state.
1. The user writes a module to tell wtf how to insert a test case in the target. wtf provides basic features like reading physical and virtual memory ranges, read and write registers, etc. The user also defines exit conditions to tell the fuzzer when to stop executing test cases.
1. wtf runs the targeted code, tracks code coverage, detects crashes, and tracks dirty memory.
1. wtf restores the dirty physical memory from the kernel crash dump and resets the CPU state. It generates a new test case, rinse & repeat.

After laying out the plan, I realized that I didn't have code that parsed Windows kernel-crash dump which is essential for wtf. So I wrote [kdmp-parser](https://github.com/0vercl0k/kdmp-parser) which is a C++ library that parses Windows kernel crash dumps. I wrote it myself because I couldn't find a simple drop-in library available on the shelf. Getting physical memory is not enough because I also needed to dump the CPU state as well as MSRs, etc. Thankfully [yrp604](https://twitter.com/yrp604) had already hacked up a Windbg Javascript extension to do the work and so I reused it [bdump.js](https://github.com/yrp604/bdump).

Once I was able to extract the physical memory & the CPU state I needed an execution environment to run my target. Again, [yrp604](https://twitter.com/yrp604) was working on [bochscpu](https://github.com/yrp604/bochscpu) at the time and so I started there. [bochscpu](https://github.com/yrp604/bochscpu) is basically [bochs](https://bochs.sourceforge.io/)'s CPU available from a Rust library with C bindings (yes he kindly made bindings because I didn't want to touch any Rust). It basically is a software CPU that knows how to run intel 64-bit code, knows about segmentation, rings, MSRs, etc. It also doesn't use any of bochs devices so it is much lighter. From the start, I decided that wtf wouldn't handle any devices: no disk, no screen, no mouse, no keyboards, etc.

## Bochscpu 101

The first step was to load up the physical memory and configure the CPU of the execution environment. Memory in bochscpu is lazy: you start execution with no physical memory available and bochs invokes a callback of yours to tell you when the guest is accessing physical memory that hasn't been mapped. This is great because:

1. No need to load an entire dump of memory inside the emulator when it starts,
2. Only used memory gets mapped making the instance very light in memory usage.

I also need to introduce a few acronyms that I use everywhere:

1. GPA: Guest physical address. This is a physical address inside the guest. The guest is what is run inside the emulator.
1. GVA: Guest virtual address. This is guest virtual memory.
1. HVA: Host virtual address. This is virtual memory inside the host. The host is what runs the execution environment.

To register the callback you need to invoke `bochscpu_mem_missing_page`. The callback receives the GPA that is being accessed and you can call `bochscpu_mem_page_insert` to insert an HVA page that backs a GPA into the environment. Yes, all guest physical memory is backed by regular virtual memory that the host allocates. Here is a simple example of what the wtf callback looks like:

```c++
void StaticGpaMissingHandler(const uint64_t Gpa) {
  const Gpa_t AlignedGpa = Gpa_t(Gpa).Align();
  BochsHooksDebugPrint("GpaMissingHandler: Mapping GPA {:#x} ({:#x}) ..\n",
                       AlignedGpa, Gpa);

  const void *DmpPage =
      reinterpret_cast<BochscpuBackend_t *>(g_Backend)->GetPhysicalPage(
          AlignedGpa);
  if (DmpPage == nullptr) {
    BochsHooksDebugPrint(
        "GpaMissingHandler: GPA {:#x} is not mapped in the dump.\n",
        AlignedGpa);
  }

  uint8_t *Page = (uint8_t *)aligned_alloc(Page::Size, Page::Size);
  if (Page == nullptr) {
    fmt::print("Failed to allocate memory in GpaMissingHandler.\n");
    __debugbreak();
  }

  if (DmpPage) {

    //
    // Copy the dump page into the new page.
    //

    memcpy(Page, DmpPage, Page::Size);

  } else {

    //
    // Fake it 'till you make it.
    //

    memset(Page, 0, Page::Size);
  }

  //
  // Tell bochscpu that we inserted a page backing the requested GPA.
  //

  bochscpu_mem_page_insert(AlignedGpa.U64(), Page);
}
```

It is simple: 

1. we allocate a page of memory with `aligned_alloc` as bochs requires page-aligned memory,
1. we populate its content using the crash dump.
1. we assume that if the guest accesses physical memory that isn't in the crash dump, it means that the OS is allocating "new" memory. We fill those pages with zeroes. We also assume that if we are wrong about that, the guest will crash in spectacular ways.

To create a context, you call `bochscpu_cpu_new` to create a virtual CPU and then `bochscpu_cpu_set_state` to set its state. This is a shortened version of `LoadState`:

```c++
void BochscpuBackend_t::LoadState(const CpuState_t &State) {
  bochscpu_cpu_state_t Bochs;
  memset(&Bochs, 0, sizeof(Bochs));

  Seed_ = State.Seed;
  Bochs.bochscpu_seed = State.Seed;
  Bochs.rax = State.Rax;
  Bochs.rbx = State.Rbx;
//...
  Bochs.rflags = State.Rflags;
  Bochs.tsc = State.Tsc;
  Bochs.apic_base = State.ApicBase;
  Bochs.sysenter_cs = State.SysenterCs;
  Bochs.sysenter_esp = State.SysenterEsp;
  Bochs.sysenter_eip = State.SysenterEip;
  Bochs.pat = State.Pat;
  Bochs.efer = uint32_t(State.Efer.Flags);
  Bochs.star = State.Star;
  Bochs.lstar = State.Lstar;
  Bochs.cstar = State.Cstar;
  Bochs.sfmask = State.Sfmask;
  Bochs.kernel_gs_base = State.KernelGsBase;
  Bochs.tsc_aux = State.TscAux;
  Bochs.fpcw = State.Fpcw;
  Bochs.fpsw = State.Fpsw;
  Bochs.fptw = State.Fptw;
  Bochs.cr0 = uint32_t(State.Cr0.Flags);
  Bochs.cr2 = State.Cr2;
  Bochs.cr3 = State.Cr3;
  Bochs.cr4 = uint32_t(State.Cr4.Flags);
  Bochs.cr8 = State.Cr8;
  Bochs.xcr0 = State.Xcr0;
  Bochs.dr0 = State.Dr0;
  Bochs.dr1 = State.Dr1;
  Bochs.dr2 = State.Dr2;
  Bochs.dr3 = State.Dr3;
  Bochs.dr6 = State.Dr6;
  Bochs.dr7 = State.Dr7;
  Bochs.mxcsr = State.Mxcsr;
  Bochs.mxcsr_mask = State.MxcsrMask;
  Bochs.fpop = State.Fpop;

#define SEG(_Bochs_, _Whv_)                                                    \
  {                                                                            \
    Bochs._Bochs_.attr = State._Whv_.Attr;                                     \
    Bochs._Bochs_.base = State._Whv_.Base;                                     \
    Bochs._Bochs_.limit = State._Whv_.Limit;                                   \
    Bochs._Bochs_.present = State._Whv_.Present;                               \
    Bochs._Bochs_.selector = State._Whv_.Selector;                             \
  }

  SEG(es, Es);
  SEG(cs, Cs);
  SEG(ss, Ss);
  SEG(ds, Ds);
  SEG(fs, Fs);
  SEG(gs, Gs);
  SEG(tr, Tr);
  SEG(ldtr, Ldtr);

#undef SEG

#define GLOBALSEG(_Bochs_, _Whv_)                                              \
  {                                                                            \
    Bochs._Bochs_.base = State._Whv_.Base;                                     \
    Bochs._Bochs_.limit = State._Whv_.Limit;                                   \
  }

  GLOBALSEG(gdtr, Gdtr);
  GLOBALSEG(idtr, Idtr);

  // ...
  bochscpu_cpu_set_state(Cpu_, &Bochs);
}
```

In order to register various hooks, you need a chain of `bochscpu_hooks_t` structures. For example, wtf registers them like this:

```c++
//
// Prepare the hooks.
//

Hooks_.ctx = this;
Hooks_.after_execution = StaticAfterExecutionHook;
Hooks_.before_execution = StaticBeforeExecutionHook;
Hooks_.lin_access = StaticLinAccessHook;
Hooks_.interrupt = StaticInterruptHook;
Hooks_.exception = StaticExceptionHook;
Hooks_.phy_access = StaticPhyAccessHook;
Hooks_.tlb_cntrl = StaticTlbControlHook;
```

I don't want to describe every hook but we get notified every time an instruction is executed and every time physical or virtual memory is accessed. The hooks are documented in [instrumentation.txt](https://bochs.sourceforge.io/cgi-bin/lxr/source/instrument/instrumentation.txt) if you are curious. As an example, this is the mechanism used to provide full system code coverage:

```c++
void BochscpuBackend_t::BeforeExecutionHook(
        /*void *Context, */ uint32_t, void *) {

  //
  // Grab the rip register off the cpu.
  //

  const Gva_t Rip = Gva_t(bochscpu_cpu_rip(Cpu_));

  //
  // Keep track of new code coverage or log into the trace file.
  //

  const auto &Res = AggregatedCodeCoverage_.emplace(Rip);
  if (Res.second) {
    LastNewCoverage_.emplace(Rip);
  }

  // ...
}
```

Once the hook chain is configured, you start execution of the guest with `bochscpu_cpu_run`:

```c++
//
// Lift off.
//

bochscpu_cpu_run(Cpu_, HookChain_);
```

Great, we're now pros and we can run some code!

## Building the basics

In this part, I focus on the various fundamental blocks that we need to develop for the fuzzer to work and be useful.

**Memory access facilities**

As mentioned in the introduction, the user needs to tell the fuzzer how to insert a test case into its target. As a result, the user needs to be able to read & write physical and virtual memory.

Let's start with the easy one. To write into guest physical memory we need to find the backing HVA page. bochscpu uses a dictionary to map GPA to HVA pages that we can query using `bochscpu_mem_phy_translate`. Keep in mind that two adjacent GPA pages are not necessarily adjacent in the host address space, that is why writing across two pages needs extra care.

Writing to virtual memory is trickier because we need to know the backing GPAs. This means emulating the MMU and parsing the page tables. This gives us GPAs and we know how to write in this space. Same as above, writing across two pages needs extra care.

**Instrumenting execution flow**

Being able to instrument the target is very important because both the user and wtf itself need this to implement features. For example, crash detection is implemented by wtf using breakpoints in strategic areas. Another example, the user might also need to skip a function call and fake a return value.
Implementing breakpoints in an emulator is easy as we receive a notification when an instruction is executed. This is the perfect spot to check if we have a registered breakpoint at this address and invoke a callback if so:

```c++
void BochscpuBackend_t::BeforeExecutionHook(
        /*void *Context, */ uint32_t, void *) {

  //
  // Grab the rip register off the cpu.
  //

  const Gva_t Rip = Gva_t(bochscpu_cpu_rip(Cpu_));

  // ...

  //
  // Handle breakpoints.
  //

  if (Breakpoints_.contains(Rip)) {
    Breakpoints_.at(Rip)(this);
  }
}
```

**Handling infinite loop**

To protect the fuzzer against infinite loops, the `AfterExecutionHook` hook is used to count instructions. This allows us to limit test case execution:

```c++
void BochscpuBackend_t::AfterExecutionHook(/*void *Context, */ uint32_t,
                                           void *) {

  //
  // Keep track of the instructions executed.
  //

  RunStats_.NumberInstructionsExecuted++;

  //
  // Check the instruction limit.
  //

  if (InstructionLimit_ > 0 &&
      RunStats_.NumberInstructionsExecuted > InstructionLimit_) {

    //
    // If we're over the limit, we stop the cpu.
    //

    BochsHooksDebugPrint("Over the instruction limit ({}), stopping cpu.\n",
                         InstructionLimit_);
    TestcaseResult_ = Timedout_t();
    bochscpu_cpu_stop(Cpu_);
  }
}
```

**Tracking code coverage**

Again, getting full system code coverage with bochscpu is very easy thanks to the hook points. Every time an instruction is executed we add the address into a set:

```c++
void BochscpuBackend_t::BeforeExecutionHook(
        /*void *Context, */ uint32_t, void *) {

  //
  // Grab the rip register off the cpu.
  //

  const Gva_t Rip = Gva_t(bochscpu_cpu_rip(Cpu_));

  //
  // Keep track of new code coverage or log into the trace file.
  //

  const auto &Res = AggregatedCodeCoverage_.emplace(Rip);
  if (Res.second) {
    LastNewCoverage_.emplace(Rip);
  }
```

**Tracking dirty memory**

wtf tracks dirty memory to be able to restore state fast. Instead of restoring the entire physical memory, we simply restore the memory that has changed since the beginning of the execution. One of the hook points notifies us when the guest accesses memory, so it is easy to know which memory gets written to. 

```c++
void BochscpuBackend_t::LinAccessHook(/*void *Context, */ uint32_t,
                                      uint64_t VirtualAddress,
                                      uint64_t PhysicalAddress, uintptr_t Len,
                                      uint32_t, uint32_t MemAccess) {

  // ...

  //
  // If this is not a write access, we don't care to go further.
  //

  if (MemAccess != BOCHSCPU_HOOK_MEM_WRITE &&
      MemAccess != BOCHSCPU_HOOK_MEM_RW) {
    return;
  }

  //
  // Adding the physical address the set of dirty GPAs.
  // We don't use DirtyVirtualMemoryRange here as we need to
  // do a GVA->GPA translation which is a bit costly.
  //

  DirtyGpa(Gpa_t(PhysicalAddress));
}
```

Note that accesses straddling pages aren't handled in this callback because bochs delivers one call per page. Once wtf knows which pages are dirty, restoring is easy:

```c++
bool BochscpuBackend_t::Restore(const CpuState_t &CpuState) {
  // ...
  //
  // Restore physical memory.
  //

  uint8_t ZeroPage[Page::Size];
  memset(ZeroPage, 0, sizeof(ZeroPage));
  for (const auto DirtyGpa : DirtyGpas_) {
    const uint8_t *Hva = DmpParser_.GetPhysicalPage(DirtyGpa.U64());

    //
    // As we allocate physical memory pages full of zeros when
    // the guest tries to access a GPA that isn't present in the dump,
    // we need to be able to restore those. It's easy, if the Hva is nullptr,
    // we point it to a zero page.
    //

    if (Hva == nullptr) {
      Hva = ZeroPage;
    }

    bochscpu_mem_phy_write(DirtyGpa.U64(), Hva, Page::Size);
  }

  //
  // Empty the set.
  //

  DirtyGpas_.clear();

  // ...
  return true;
}
```

**Generic mutators**

I think generic mutators are great but I didn't want to spend too much time worrying about them. Ultimately I think you get more value out of writing a domain-specific generator and building a diverse high-quality corpus. So I simply ripped off [libfuzzer](https://www.llvm.org/docs/LibFuzzer.html)'s and [honggfuzz](https://honggfuzz.dev/)'s.

```c++
class LibfuzzerMutator_t {
  using CustomMutatorFunc_t =
      decltype(fuzzer::ExternalFunctions::LLVMFuzzerCustomMutator);
  fuzzer::Random Rand_;
  fuzzer::MutationDispatcher Mut_;
  std::unique_ptr<fuzzer::Unit> CrossOverWith_;

public:
  explicit LibfuzzerMutator_t(std::mt19937_64 &Rng);

  size_t Mutate(uint8_t *Data, const size_t DataLen, const size_t MaxSize);
  void RegisterCustomMutator(const CustomMutatorFunc_t F);
  void SetCrossOverWith(const Testcase_t &Testcase);
};

class HonggfuzzMutator_t {
  honggfuzz::dynfile_t DynFile_;
  honggfuzz::honggfuzz_t Global_;
  std::mt19937_64 &Rng_;
  honggfuzz::run_t Run_;

public:
  explicit HonggfuzzMutator_t(std::mt19937_64 &Rng);
  size_t Mutate(uint8_t *Data, const size_t DataLen, const size_t MaxSize);
  void SetCrossOverWith(const Testcase_t &Testcase);
};
```

**Corpus store**

Code coverage in wtf is basically the fitness function. Every test case that generates new code coverage is added to the corpus. The code that keeps track of the corpus is basically a glorified list of test cases that are kept in memory.

The main loop asks for a test case from the corpus which gets mutated by one of the generic mutators and finally runs into one of the execution environments. If the test case generated new coverage it gets added to the corpus store - nothing fancy.

```c++
    //
    // If the coverage size has changed, it means that this testcase
    // provided new coverage indeed.
    //

    const bool NewCoverage = Coverage_.size() > SizeBefore;
    if (NewCoverage) {

      //
      // Allocate a test that will get moved into the corpus and maybe
      // saved on disk.
      //

      Testcase_t Testcase((uint8_t *)ReceivedTestcase.data(),
                          ReceivedTestcase.size());

      //
      // Before moving the buffer into the corpus, set up cross over with
      // it.
      //

      Mutator_->SetCrossOverWith(Testcase);

      //
      // Ready to move the buffer into the corpus now.
      //

      Corpus_.SaveTestcase(Result, std::move(Testcase));
    }
  }

  // [...]

  //
  // If we get here, it means that we are ready to mutate.
  // First thing we do is to grab a seed.
  //

  const Testcase_t *Testcase = Corpus_.PickTestcase();
  if (!Testcase) {
    fmt::print("The corpus is empty, exiting\n");
    std::abort();
  }

  //
  // If the testcase is too big, abort as this should not happen.
  //

  if (Testcase->BufferSize_ > Opts_.TestcaseBufferMaxSize) {
    fmt::print(
        "The testcase buffer len is bigger than the testcase buffer max "
        "size.\n");
    std::abort();
  }

  //
  // Copy the input in a buffer we're going to mutate.
  //

  memcpy(ScratchBuffer_.data(), Testcase->Buffer_.get(),
          Testcase->BufferSize_);

  //
  // Mutate in the scratch buffer.
  //

  const size_t TestcaseBufferSize =
      Mutator_->Mutate(ScratchBuffer_.data(), Testcase->BufferSize_,
                        Opts_.TestcaseBufferMaxSize);

  //
  // Copy the testcase in its own buffer before sending it to the
  // consumer.
  //

  TestcaseContent.resize(TestcaseBufferSize);
  memcpy(TestcaseContent.data(), ScratchBuffer_.data(), TestcaseBufferSize);
```

**Detecting context switches**

Because we are running an entire OS, we want to avoid spending time executing things that aren't of interest to our purpose. If you are fuzzing `ida64.exe` you don't really care about executing `explorer.exe` code. For this reason, we look for `cr3` changes thanks to the `TlbControlHook` callback and stop execution if needed:

```c++
void BochscpuBackend_t::TlbControlHook(/*void *Context, */ uint32_t,
                                       uint32_t What, uint64_t NewCrValue) {

  //
  // We only care about CR3 changes.
  //

  if (What != BOCHSCPU_HOOK_TLB_CR3) {
    return;
  }

  //
  // And we only care about it when the CR3 value is actually different from
  // when we started the testcase.
  //

  if (NewCrValue == InitialCr3_) {
    return;
  }

  //
  // Stop the cpu as we don't want to be context-switching.
  //

  BochsHooksDebugPrint("The cr3 register is getting changed ({:#x})\n",
                       NewCrValue);
  BochsHooksDebugPrint("Stopping cpu.\n");
  TestcaseResult_ = Cr3Change_t();
  bochscpu_cpu_stop(Cpu_);
}
```

**Debug symbols**

Imagine yourself fuzzing a target with wtf now. You need to write a fuzzer module in order to tell wtf how to feed a testcase to your target. To do that, you might need to read some global states to retrieve some offsets of some critical structures. We've built memory access facilities so you can definitely do that but you have to hardcode addresses. This gets in the way really fast when you are taking different snapshots, porting the fuzzer to a new version of the targeted software, etc. 

This was identified early on as a big pain point for the user and I needed a way to not hardcode things that didn't need to be hardcoded. To address this problem, on Windows I use the `IDebugClient` / `IDebugControl` COM objects that allow programmatic use of `dbghelp` and `dbgeng` features. You can load a crash dump, evaluate and resolve symbols, etc. This is what the [Debugger_t](https://github.com/0vercl0k/wtf/blob/main/src/wtf/debugger.h#L57) class does.

**Trace generation**

The most annoying thing for me was that execution backends are extremely opaque. It is really hard to see what's going on within them. Actually, if you have ever tried to use whv / kvm APIs you probably ran into the case where the API tells you that you loaded a 'wrong' CPU state. It might be an MSR not configured right, a weird segment descriptor, etc. Figuring out where the issue comes from is both painful and frustrating.

Not knowing what's happening is also annoying when the guest is bug-checking inside the backend. To address the lack of transparency I decided to generate execution traces that I could use for debugging. It is very rudimentary yet very useful to verify that the execution inside the backend is correct. In addition to this tool, you can always modify your module to add strategic breakpoints and dump registers when you want. Those traces are pretty cool because you get to follow everything that happens in the system: from user-mode to kernel-mode, the page-fault handler, etc.

Those traces are also used to be loaded in [lighthouse](https://github.com/gaasedelen/lighthouse) to analyze the coverage generated by a particular test case.

**Crash detection**

The last basic block that I needed was user-mode crash detection. I had done [some](https://doar-e.github.io/blog/2013/10/12/having-a-look-at-the-windows-userkernel-exceptions-dispatcher/) past [work](https://github.com/googleprojectzero/winafl/blob/master/afl-staticinstr.c#L108) in the user exception handler so I kind of knew my way around it. I decided to hook `ntdll!RtlDispatchException` & `nt!KiRaiseSecurityCheckFailure` to detect fail-fast exceptions that can be triggered from stack cookie check failure.

# Harnessing IDA: walking barefoot into the desert

Once I was done writing the basic features, I started to harness IDA. I knew I wanted to target the loader plugins and based on their sizes as well as past vulnerabilities it felt like looking at ELF was my best chance.

I initially started to harness IDA with its GUI and everything. In retrospect, this was bonkers as I remember handling tons of weird things related to Qt and win32k. After a few weeks of making progress here and there I realized that IDA had a few options to make my life easier:

- `IDA_NO_HISTORY=1` meant that I didn't have to handle as many registry accesses,
- The `-B` option allows running IDA in batch-mode from the command line,
- `TVHEADLESS=1` also helped a lot regarding GUI/Qt stuff I was working around.

Some of those options were documented later this year by Igor in this blog post: [Igor’s tip of the week #08: Batch mode under the hood](https://hex-rays.com/blog/igor-tip-of-the-week-08-batch-mode-under-the-hood/).

## Inserting test case

After finding out those it immediately felt like harnessing was possible again. The main problem I had was that IDA reads the input file lazily via `fread`, `fseek`, etc. It also reads a bunch of other things like configuration files, the license file, etc.

To be able to deliver my test cases I implemented a layer of hooks that allowed me to pass through file i/o from the guest to my host. This allowed me to read my IDA license keys, the configuration files as well as my input. It also meant that I could sink file writes made to the `.id0`, `.id1`, `.nam`, and all the files that IDA generates that I didn't care about. This was quite a bit of work and it was not really fun work either.

I was not a big fan of this pass through layer because I was worried that a bug in my code could mean overwriting files on my host or lead to that kind of badness. That is why I decided to replace this pass-through layer by reading from memory buffers. During startup, wtf reads the actual files into buffers and the file-system hooks deliver the bytes as needed. You can see this work in [fshooks.cc](https://github.com/0vercl0k/wtf/blob/main/src/wtf/fshooks.cc).

This is an example of what this layer allowed me to do:

```c++
bool Ida64ConfigureFsHandleTable(const fs::path &GuestFilesPath) {

  //
  // Those files are files we want to redirect to host files. When there is
  // a hooked i/o targeted to one of them, we deliver the i/o on the host
  // by calling the appropriate syscalls and proxy back the result to the
  // guest.
  //

  const std::vector<std::u16string> GuestFiles = {
      uR"(\??\C:\Program Files\IDA Pro 7.5\ida.key)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\cfg\ida.cfg)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\cfg\noret.cfg)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\cfg\pe.cfg)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\plugins\plugins.cfg)"};

  for (const auto &GuestFile : GuestFiles) {
    const size_t LastSlash = GuestFile.find_last_of(uR"(\)");
    if (LastSlash == GuestFile.npos) {
      fmt::print("Expected a / in {}\n", u16stringToString(GuestFile));
      return false;
    }

    const std::u16string GuestFilename = GuestFile.substr(LastSlash + 1);
    const fs::path HostFile(GuestFilesPath / GuestFilename);

    size_t BufferSize = 0;
    const auto Buffer = ReadFile(HostFile, BufferSize);
    if (Buffer == nullptr || BufferSize == 0) {
      fmt::print("Expected to find {}.\n", HostFile.string());
      return false;
    }

    g_FsHandleTable.MapExistingGuestFile(GuestFile.c_str(), Buffer.get(),
                                         BufferSize);
  }

  g_FsHandleTable.MapExistingWriteableGuestFile(
      uR"(\??\C:\Users\over\Desktop\wtf_input.id0)");
  g_FsHandleTable.MapNonExistingGuestFile(
      uR"(\??\C:\Users\over\Desktop\wtf_input.id1)");
  g_FsHandleTable.MapNonExistingGuestFile(
      uR"(\??\C:\Users\over\Desktop\wtf_input.nam)");
  g_FsHandleTable.MapNonExistingGuestFile(
      uR"(\??\C:\Users\over\Desktop\wtf_input.id2)");

  //
  // Those files are files we want to pretend that they don't exist in the
  // guest.
  //

  const std::vector<std::u16string> NotFounds = {
      uR"(\??\C:\Program Files\IDA Pro 7.5\ida64.int)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\ids\idsnames)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\ids\epoc.zip)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\ids\epoc6.zip)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\ids\epoc9.zip)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\ids\flirt.zip)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\ids\geos.zip)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\ids\linux.zip)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\ids\os2.zip)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\ids\win.zip)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\ids\win7.zip)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\ids\wince.zip)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\loaders\hppacore.idc)",
      uR"(\??\C:\Users\over\AppData\Roaming\Hex-Rays\IDA Pro\proccache64.lst)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\cfg\Latin_1.clt)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\cfg\dwarf.cfg)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\ids\)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\cfg\atrap.cfg)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\cfg\hpux.cfg)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\cfg\i960.cfg)",
      uR"(\??\C:\Program Files\IDA Pro 7.5\cfg\goodname.cfg)"};

  for (const std::u16string &NotFound : NotFounds) {
    g_FsHandleTable.MapNonExistingGuestFile(NotFound.c_str());
  }

  g_FsHandleTable.SetBlacklistDecisionHandler([](const std::u16string &Path) {
    // \ids\pc\api-ms-win-core-profile-l1-1-0.idt
    // \ids\api-ms-win-core-profile-l1-1-0.idt
    // \sig\pc\vc64seh.sig
    // \til\pc\gnulnx_x64.til
    // 6ba8075c8f243566350f741c7d6e9318089add.debug
    const bool IsIdt = Path.ends_with(u".idt");
    const bool IsIds = Path.ends_with(u".ids");
    const bool IsSig = Path.ends_with(u".sig");
    const bool IsTil = Path.ends_with(u".til");
    const bool IsDebug = Path.ends_with(u".debug");
    const bool Blacklisted = IsIdt || IsIds || IsSig || IsTil || IsDebug;

    if (Blacklisted) {
      return true;
    }

    //
    // The parser can invoke ida64!import_module to have the user select
    // a file that gets imported by the binary currently analyzed. This is
    // fine if the import directory is well formated, when it's not it
    // potentially uses garbage in the file as a path name. Strategy here
    // is to block the access if the path is not ASCII.
    //

    for (const auto &C : Path) {
      if (isascii(C)) {
        continue;
      }

      DebugPrint("Blocking a weird NtOpenFile: {}\n", u16stringToString(Path));
      return true;
    }

    return false;
  });

  return true;
}
```

Although this was probably the most annoying problem to deal with, I had to deal with tons more. I've decided to walk you through some of them.

**Problem 1: Pre-load dlls**

For IDA to know which loader is the right loader to use it loads all of them and asks them if they know what this file is. Remember that there is no disk when running in wtf so loading a DLL is a problem.

This problem was solved by injecting the DLLs with [inject](https://github.com/0vercl0k/inject) into IDA before generating the snapshot so that when it loads them it doesn't generate file i/o. The same problem happens with [delay-loaded DLLs](https://docs.microsoft.com/en-us/cpp/build/reference/linker-support-for-delay-loaded-dlls?view=msvc-160).

**Problem 2: Paged-out memory**

On Windows, memory can be swapped out and written to disk into the [pagefile.sys](https://docs.microsoft.com/en-us/windows/client-management/introduction-page-file) file. When somebody accesses memory that has been paged out, the access triggers a #PF which the page fault handler resolves by loading the page back up from the pagefile. But again, this generates file i/o.

I solved this problem for user-mode with [lockmem](https://github.com/0vercl0k/lockmem) which is a small utility that locks all virtual memory ranges into the process working set. As an example, this is the script I used to snapshot IDA and it highlights how I used both [inject](https://github.com/0vercl0k/inject) and [lockmem](https://github.com/0vercl0k/lockmem):

```batch
set BASE_DIR=C:\Program Files\IDA Pro 7.5
set PLUGINS_DIR=%BASE_DIR%\plugins
set LOADERS_DIR=%BASE_DIR%\loaders
set PROCS_DIR=%BASE_DIR%\procs
set NTSD=C:\Users\over\Desktop\x64\ntsd.exe

REM Remove a bunch of plugins
del "%PLUGINS_DIR%\python.dll"
del "%PLUGINS_DIR%\python64.dll"
[...]
REM Turning on PH
REM 02000000 Enable page heap (full page heap)
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ida64.exe" /v "GlobalFlag" /t REG_SZ /d "0x2000000" /f
REM This is useful to disable stack-traces
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ida64.exe" /v "PageHeapFlags" /t REG_SZ /d "0x0" /f

REM History is stored in the registry and so triggers cr3 change (when attaching to Registry process VA)
set IDA_NO_HISTORY=1
REM Set up headless mode and run IDA
set TVHEADLESS=1
REM https://www.hex-rays.com/products/ida/support/idadoc/417.shtml
start /b %NTSD% -d "%BASE_DIR%\ida64.exe" -B wtf_input

REM bp ida64!init_database
REM Bump suspend count: ~0n
REM Detach: qd
REM Find process, set ba e1 on address from kdbg
REM ntsd -pn ida64.exe ; fix suspend count: ~0m
REM should break.

REM Inject the dlls.
inject.exe ida64.exe "%PLUGINS_DIR%"
inject.exe ida64.exe "%LOADERS_DIR%"
inject.exe ida64.exe "%PROCS_DIR%"
inject.exe ida64.exe "%BASE_DIR%\libdwarf.dll"

REM Lock everything
lockmem.exe ida64.exe

REM You can now reattach; and ~0m to bump down the suspend count
%NTSD% -pn ida64.exe
```

**Problem 3: Manually soft page-fault in memory from hooks**

To insert my test cases in memory I used the file system hook layer I described above as well as virtual memory facilities that we talked about earlier. Sometimes, the caller would allocate a memory buffer and call let's say `fread` to read the file into the buffer. When `fread` was invoked, my hook triggered, and sometimes calling `VirtWrite` would fail. After debugging and inspecting the state of the PTEs it was clear that the PTE was in an invalid state. This is explained because memory is lazy on Windows. The page fault is expected to be invoked and it will fix the PTE itself and execution carries. Because we are doing the memory write ourselves, it means that we don't generate a page fault and so the page fault handler doesn't get invoked.

To solve this, I try to do a virtual to physical translation and inspect the result. If the translation is successful it means the page tables are in a good state and I can perform the memory access. If it is not, I insert a page fault in the guest and resume execution. When execution restarts, the page fault handler runs, fixes the PTE, and returns execution to the instruction that was executing before the page fault. Because we have our hook there, we get reinvoked a second time but this time the virtual to physical translation works and we can do the memory write. Here is an example in `ntdll!NtQueryAttributesFile`:

```c++
if (!g_Backend->SetBreakpoint(
        "ntdll!NtQueryAttributesFile", [](Backend_t *Backend) {
          // NTSTATUS NtQueryAttributesFile(
          //  _In_  POBJECT_ATTRIBUTES      ObjectAttributes,
          //  _Out_ PFILE_BASIC_INFORMATION FileInformation
          //);
          // ...
          //
          // Ensure that the GuestFileInformation is faulted-in memory.
          //

          if (GuestFileInformation &&
              Backend->PageFaultsMemoryIfNeeded(
                  GuestFileInformation, sizeof(FILE_BASIC_INFORMATION))) {
            return;
          }
```

**Problem 4: KVA shadow**

When I snapshot IDA the CPU is in user-mode but some of the breakpoints I set up are on functions living in kernel-mode. To be able to set a breakpoint on those, wtf simply does a `VirtTranslate` and modifies physical memory with an `int3` opcode. This is exactly what [KVA Shadow](https://msrc-blog.microsoft.com/2018/03/23/kva-shadow-mitigating-meltdown-on-windows/) prevents: the user `@cr3` doesn't contain the part of the page tables that describe kernel-mode (only a few stubs) and so there is no valid translation.

To solve this I simply disabled KVA shadow with the below edits in the registry:

```text
REM To disable mitigations for CVE-2017-5715 (Spectre Variant 2) and CVE-2017-5754 (Meltdown)
REM https://support.microsoft.com/en-us/help/4072698/windows-server-speculative-execution-side-channel-vulnerabilities
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f
```

**Problem 5: Identifying bottlenecks**

While developing wtf I allocated time to spend on profiling the tool under specific workload with the [Intel V-Tune Profiler](https://software.intel.com/content/www/us/en/develop/documentation/get-started-with-vtune/top.html) which is now free. If you have never used it, you really should as it is both absolutely fascinating and really useful. If you care about performance, you need to measure to understand better where you can have the most impact. Not measuring is a big mistake because you will most likely spend time changing code that might not even matter. If you try to optimize something you should also be able to measure the impact of your change.

For example, below is the V-Tune hotspot analysis report for the below invocation:

```text
wtf.exe run --name hevd --backend whv --state targets\hevd\state --runs=100000 --input targets\hevd\crashes\crash-0xfffff764b91c0000-0x0-0xffffbf84fb10e780-0x2-0x0
```

![vtune](/images/fuzzing_ida/whv.png)

This report is really catastrophic because it means we spend twice as much time dealing with memory access faults than actually running target code. Handling memory access faults should take very little time. If anybody knows their way around whv & performance it'd be great to reach out because I really have no idea why it is that slow.

## The birth of hope

After tons of work, I could finally execute the ELF loader from start to end and see the messages you would see in the output window. In the below, you can see IDA loading the `elf64.dll` loader then initializes the database as well as the btree. Then, it loads up processor modules, creates segments, processes relocations, and finally loads the dwarf modules to parse debug information:

```text
>wtf.exe run --name ida64-elf75 --backend whv --state state --input ntfs-3g
Initializing the debugger instance.. (this takes a bit of time)
Parsing coverage\dwarf64.cov..
Parsing coverage\elf64.cov..
Parsing coverage\libdwarf.cov..
Applied 43624 code coverage breakpoints
[...]
Running ntfs-3g
[...]
ida64: kernelbase!LoadLibraryA(C:\Program Files\IDA Pro 7.5\loaders\elf64.dll)
ida64: ida64!msg(format="Possible file format: %s (%s) ", ...)
ida64: ELF64 for x86-64 (Shared object) - ELF64 for x86-64 (Shared object)
[...]
ida64: ida64!msg(format="   bytes   pages size description --------- ----- ---- -------------------------------------------- %9lu %5u %4u allocating memory for b-tree... ", ...)
ida64: ida64!msg(format="%9u %5u %4u allocating memory for virtual array... ", ...)
ida64: ida64!msg(format="%9u %5u %4u allocating memory for name pointers... ----------------------------------------------------------------- %9u
total memory allocated  ", ...)
ida64: kernelbase!LoadLibraryA(C:\Program Files\IDA Pro 7.5\procs\78k064.dll)
ida64: kernelbase!LoadLibraryA(C:\Program Files\IDA Pro 7.5\procs\78k0s64.dll)
ida64: kernelbase!LoadLibraryA(C:\Program Files\IDA Pro 7.5\procs\ad218x64.dll)
ida64: kernelbase!LoadLibraryA(C:\Program Files\IDA Pro 7.5\procs\alpha64.dll)
[...]
ida64: ida64!msg(format="Loading file '%s' into database... Detected file format: %s ", ...)
ida64: ida64!msg(format="Loading processor module %s for %s...", ...)
ida64: ida64!msg(format="Initializing processor module %s...", ...)
ida64: ida64!msg(format="OK ", ...)
ida64: ida64!mbox(format="@0:1139[] Can't use BIOS comments base.", ...)
ida64: ida64!msg(format="%s -> %s ", ...)
ida64: ida64!msg(format="Autoanalysis subsystem has been initialized. ", ...)
ida64: ida64!msg(format="%3d. Creating a new segment  (%08a-%08a) ...", ...)
ida64: ida64!msg(format=" ... OK ", ...)
ida64: ida64!msg(format="%3d. Creating a new segment  (%08a-%08a) ...", ...)
ida64: ida64!msg(format=" ... OK ", ...)
ida64: ida64!msg(format="%s -> %s ", ...)
[...]
ida64: ida64!msg(format="%3d. Creating a new segment  (%08a-%08a) ...", ...)
ida64: ida64!msg(format=" ... OK ", ...)
ida64: ida64!msg(format="%3d. Creating a new segment  (%08a-%08a) ...", ...)
ida64: ida64!msg(format=" ... OK ", ...)
ida64: ida64!msg(format="%3d. Creating a new segment  (%08a-%08a) ...", ...)
ida64: ida64!msg(format=" ... OK ", ...)
ida64: ida64!msg(format="%3d. Creating a new segment  (%08a-%08a) ...", ...)
ida64: ida64!msg(format=" ... OK ", ...)
ida64: ida64!msg(format="%3d. Creating a new segment  (%08a-%08a) ...", ...)
ida64: ida64!msg(format=" ... OK ", ...)
ida64: ida64!mbox(format="Reading symbols", ...)
ida64: ida64!msg(format="%3d. Creating a new segment  (%08a-%08a) ...", ...)
ida64: ida64!msg(format=" ... OK ", ...)
ida64: ida64!mbox(format="Loading symbols", ...)
ida64: ida64!msg(format="%3d. Creating a new segment  (%08a-%08a) ...", ...)
ida64: ida64!msg(format=" ... OK ", ...)
ida64: ida64!mbox(format="", ...)
ida64: ida64!msg(format="Processing relocations... ", ...)
ida64: ida64!msg(format="%a: could not patch the PLT stub; unexpected PLT format or the file has been modified after linking! ", ...)
ida64: ida64!mbox(format="Unexpected entries in the PLT stub. The file might have been modified after linking.", ...)
ida64: ida64!msg(format="%s -> %s ", ...)
ida64: Unexpected entries in the PLT stub.
The file might have been modified after linking.
ida64: ida64!msg(format="%a: could not patch the PLT stub; unexpected PLT format or the file has been modified after linking! ", ...)
[...]
ida64: ida64!msg(format="%a: could not patch the PLT stub; unexpected PLT format or the file has been modified after linking! ", ...)
ida64: ida64!msg(format="%a: could not patch the PLT stub; unexpected PLT format or the file has been modified after linking! ", ...)
ida64: ida64!msg(format="%a: could not patch the PLT stub; unexpected PLT format or the file has been modified after linking! ", ...)
ida64: ida64!msg(format="%a: could not patch the PLT stub; unexpected PLT format or the file has been modified after linking! ", ...)
ida64: kernelbase!LoadLibraryA(C:\Program Files\IDA Pro 7.5\plugins\dbg64.dll)
ida64: kernelbase!LoadLibraryA(C:\Program Files\IDA Pro 7.5\plugins\dwarf64.dll)
ida64: kernelbase!LoadLibraryA(C:\Program Files\IDA Pro 7.5\libdwarf.dll)
ida64: ida64!msg(format="%s", ...)
ida64: ida64!msg(format="no. ", ...)
ida64: ida64!msg(format="%s", ...)
ida64: ida64!msg(format="no. ", ...)
ida64: ida64!msg(format="Plugin "%s" not found ", ...)
ida64: Hit the end of load file :o
```

# Need for speed: whv backend

At this point, I was able to fuzz IDA but the speed was incredibly slow. I could execute about 0.01 test cases per second. It was really cool to see it working, finding new code coverage, etc. but I felt I wouldn't find much at this speed. That's why I decided to look at using whv to implement an execution backend.

I had played around with whv before with [pywinhv](https://github.com/0vercl0k/pywinhv) so I knew the features offered by the API well. As this was the first execution backend using virtualization I had to rethink a bunch of the fundamentals.

**Code coverage**

What I settled for is to use one-time software breakpoints at the beginning of basic blocks. The user simply needs to generate a list of breakpoint addresses into a JSON file and wtf consumes this file during initialization. This means that the user can selectively pick the modules that it wants coverage for.

It is annoying though because it means you need to throw those modules in IDA and generate the JSON file for each of them. The script I use for that is available here: [gen_coveragefile_ida.py](https://github.com/0vercl0k/wtf/blob/main/scripts/gen_coveragefile_ida.py). You could obviously generate the file yourself via other tools.

Overall I think it is a good enough tradeoff. I did try to play with more creative & esoteric ways to acquire code coverage though. Filling the address space with `int3`s and lazily populating code leveraging a length-disassembler engine to know the size of instructions. I loved this idea but I ran into tons of problems with switch tables that embed data in code sections. This means that wtf corrupts them when setting software breakpoints which leads to a bunch of spectacular crashes a little bit everywhere in the system, so I abandoned this idea. The trap flag was awfully slow and whv doesn't expose the Monitor Trap Flag.

The ideal for me would be to find a way to conserve the performance and acquire code coverage without knowing anything about the target, like in bochscpu.

**Dirty memory**

The other thing that I needed was to be able to track dirty memory. whv provides [WHvQueryGpaRangeDirtyBitmap](https://docs.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvquerygparangedirtybitmap) to do just that which was perfect.

**Tracing**

One thing that I would have loved was to be able to generate execution traces like with bochscpu. I initially thought I'd be able to mirror this functionality using the trap flag. If you turn on the trap flag, let's say a `syscall` instruction, the fault gets raised after the instruction and so you miss the entire kernel side executing. I discovered that this is due to how `syscall` is implemented: it masks RFLAGS with the `IA32_FMASK` MSR stripping away the trap flag. After programming `IA32_FMASK` myself I could trace through syscalls which was great. By comparing traces generated by the two backends, I noticed that the whv trace was missing page faults. This is basically another instance of the same problem: when an interruption happens the CPU saves the current context and loads a new one from the task segment which doesn't have the trap flag. I can't remember if I got that working or if this turned out to be harder than it looked but I ended up reverting the code and settled for only generating code coverage traces. It is definitely something I would love to revisit in the future.

**Timeout**

To protect the fuzzer against infinite loops and to limit the execution time, I use a timer to tell the virtual processor to stop execution. This is also not as good as what bochscpu offered us because not as precise but that's the only solution I could come up with:

```C++
class TimerQ_t {
  HANDLE TimerQueue_ = nullptr;
  HANDLE LastTimer_ = nullptr;

  static void CALLBACK AlarmHandler(PVOID, BOOLEAN) {
    reinterpret_cast<WhvBackend_t *>(g_Backend)->CancelRunVirtualProcessor();
  }

public:
  ~TimerQ_t() {
    if (TimerQueue_) {
      DeleteTimerQueueEx(TimerQueue_, nullptr);
    }
  }

  TimerQ_t() = default;
  TimerQ_t(const TimerQ_t &) = delete;
  TimerQ_t &operator=(const TimerQ_t &) = delete;

  void SetTimer(const uint32_t Seconds) {
    if (Seconds == 0) {
      return;
    }

    if (!TimerQueue_) {
      TimerQueue_ = CreateTimerQueue();
      if (!TimerQueue_) {
        fmt::print("CreateTimerQueue failed.\n");
        exit(1);
      }
    }

    if (!CreateTimerQueueTimer(&LastTimer_, TimerQueue_, AlarmHandler,
                                nullptr, Seconds * 1000, Seconds * 1000, 0)) {
      fmt::print("CreateTimerQueueTimer failed.\n");
      exit(1);
    }
  }

  void TerminateLastTimer() {
    DeleteTimerQueueTimer(TimerQueue_, LastTimer_, nullptr);
  }
};

```

**Inserting page faults**

To be able to insert a page fault into the guest I use the `WHvRegisterPendingEvent` register and a `WHvX64PendingEventException` event type:

```C++
bool WhvBackend_t::PageFaultsMemoryIfNeeded(const Gva_t Gva,
                                            const uint64_t Size) {
  const Gva_t PageToFault = GetFirstVirtualPageToFault(Gva, Size);

  //
  // If we haven't found any GVA to fault-in then we have no job to do so we
  // return.
  //

  if (PageToFault == Gva_t(0xffffffffffffffff)) {
    return false;
  }

  WhvDebugPrint("Inserting page fault for GVA {:#x}\n", PageToFault);

  // cf 'VM-Entry Controls for Event Injection' in Intel 3C
  WHV_REGISTER_VALUE_t Exception;
  Exception->ExceptionEvent.EventPending = 1;
  Exception->ExceptionEvent.EventType = WHvX64PendingEventException;
  Exception->ExceptionEvent.DeliverErrorCode = 1;
  Exception->ExceptionEvent.Vector = WHvX64ExceptionTypePageFault;
  Exception->ExceptionEvent.ErrorCode = ErrorWrite | ErrorUser;
  Exception->ExceptionEvent.ExceptionParameter = PageToFault.U64();

  if (FAILED(SetRegister(WHvRegisterPendingEvent, &Exception))) {
    __debugbreak();
  }

  return true;
}
```

**Determinism**

The last feature that I wanted was to try to get as much determinism as I could. After tracing a bunch of executions I realized `nt!ExGenRandom` uses `rdrand` in the Windows kernel and this was a big source of non-determinism in executions. Intel does support generating vmexit when the instruction is called but this is also not exposed by whv.

I settled for a breakpoint on the function and emulate its behavior with a deterministic implementation:

```c++
//
// Make ExGenRandom deterministic.
//
// kd> ub fffff805`3b8287c4 l1
// nt!ExGenRandom+0xe0:
// fffff805`3b8287c0 480fc7f2        rdrand  rdx
const Gva_t ExGenRandom = Gva_t(g_Dbg.GetSymbol("nt!ExGenRandom") + 0xe4);
if (!g_Backend->SetBreakpoint(ExGenRandom, [](Backend_t *Backend) {
      DebugPrint("Hit ExGenRandom!\n");
      Backend->Rdx(Backend->Rdrand());
    })) {
  return false;
}
```

I am not a huge fan of this solution because it means you need to know where non-determinism is coming from which is usually hard to figure out in the first place. Another source of non-determinism is the timestamp counter. As far as I can tell, this hasn't led to any major issues though but this might bite us in the future.

With the above implemented, I was able to run test cases through the backend end to end which was great. Below I describe some of the problems I solved while testing it.

**Problem 6: Code coverage breakpoints not free**

Profiling wtf revealed that my code coverage breakpoints that I thought free were not quite that free. The theory is that they are one-time breakpoints and as a result, you pay for their cost only once. This leads to a warm-up cost that you pay at the start of the run as the fuzzer is discovering sections of code highly reachable. But if you look at it over time, it should become free.

The problem in my implementation was in the code used to restore those breakpoints after executing a test case. I tracked the code coverage breakpoints that haven't been hit in a list. When restoring, I would start by restoring every dirty page and I would iterate through this list to reset the code-coverage breakpoints. It turns out this was highly inefficient when you have hundreds of thousands of breakpoints.

I did what you usually do when you have a performance problem: I traded CPU time for memory. The answer to this problem is the [Ram_t](https://github.com/0vercl0k/wtf/blob/main/src/wtf/ram.h) class. The way it works is that every time you add a code coverage breakpoint, it duplicates the page and sets a breakpoint in this page as well as the guest RAM.

```c++
//
// Add a breakpoint to a GPA.
//

uint8_t *AddBreakpoint(const Gpa_t Gpa) {
  const Gpa_t AlignedGpa = Gpa.Align();
  uint8_t *Page = nullptr;

  //
  // Grab the page if we have it in the cache
  //

  if (Cache_.contains(Gpa.Align())) {
    Page = Cache_.at(AlignedGpa);
  }

  //
  // Or allocate and initialize one!
  //

  else {
    Page = (uint8_t *)aligned_alloc(Page::Size, Page::Size);
    if (Page == nullptr) {
      fmt::print("Failed to call aligned_alloc.\n");
      return nullptr;
    }

    const uint8_t *Virgin =
        Dmp_.GetPhysicalPage(AlignedGpa.U64()) + AlignedGpa.Offset().U64();
    if (Virgin == nullptr) {
      fmt::print(
          "The dump does not have a page backing GPA {:#x}, exiting.\n",
          AlignedGpa);
      return nullptr;
    }

    memcpy(Page, Virgin, Page::Size);
  }

  //
  // Apply the breakpoint.
  //

  const uint64_t Offset = Gpa.Offset().U64();
  Page[Offset] = 0xcc;
  Cache_.emplace(AlignedGpa, Page);

  //
  // And also update the RAM.
  //

  Ram_[Gpa.U64()] = 0xcc;
  return &Page[Offset];
}
```

When a code coverage breakpoint is hit, the class removes the breakpoint from both of those locations.

```c++
//
// Remove a breakpoint from a GPA.
//

void RemoveBreakpoint(const Gpa_t Gpa) {
  const uint8_t *Virgin = GetHvaFromDump(Gpa);
  uint8_t *Cache = GetHvaFromCache(Gpa);

  //
  // Update the RAM.
  //

  Ram_[Gpa.U64()] = *Virgin;

  //
  // Update the cache. We assume that an entry is available in the cache.
  //

  *Cache = *Virgin;
}
```

When you restore dirty memory, you simply iterate through the dirty page and ask the *Ram_t* class to restore the content of this page. Internally, the class checks if the page has been duplicated and if so it restores from this copy. If it doesn't have, it restores the content from the dump file. This lets us restore code coverage breakpoints at extra memory costs:

```c++
//
// Restore a GPA from the cache or from the dump file if no entry is
// available in the cache.
//

const uint8_t *Restore(const Gpa_t Gpa) {
  //
  // Get the HVA for the page we want to restore.
  //

  const uint8_t *SrcHva = GetHva(Gpa);

  //
  // Get the HVA for the page in RAM.
  //

  uint8_t *DstHva = Ram_ + Gpa.Align().U64();

  //
  // It is possible for a GPA to not exist in our cache and in the dump file.
  // For this to make sense, you have to remember that the crash-dump does not
  // contain the whole amount of RAM. In which case, the guest OS can decide
  // to allocate new memory backed by physical pages that were not dumped
  // because not currently used by the OS.
  //
  // When this happens, we simply zero initialize the page as.. this is
  // basically the best we can do. The hope is that if this behavior is not
  // correct, the rest of the execution simply explodes pretty fast.
  //

  if (!SrcHva) {
    memset(DstHva, 0, Page::Size);
  }

  //
  // Otherwise, this is straight forward, we restore the source into the
  // destination. If we had a copy, then that is what we are writing to the
  // destination, and if we didn't have a copy then we are restoring the
  // content from the crash-dump.
  //

  else {
    memcpy(DstHva, SrcHva, Page::Size);
  }

  //
  // Return the HVA to the user in case it needs to know about it.
  //

  return DstHva;
}
```

**Problem 7: Code coverage with IDA**

I mentioned above that I was using IDA to generate the list of code coverage breakpoints that wtf needed. At first, I thought this was a bulletproof technique but I encountered a pretty annoying bug where IDA was tagging switch-tables as code instead of data. This leads to wtf corrupting switch-tables with `cc`'s and it led to the guest crashing in spectacular ways.

I haven't run into this bug with the latest version of IDA yet which was nice.

**Problem 8: Rounds of optimization**

After profiling the fuzzer, I noticed that [WHvQueryGpaRangeDirtyBitmap](https://docs.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvquerygparangedirtybitmap) was extremely slow for unknown reasons.

To fix this, I ended up emulating the feature by mapping memory as read / execute in the EPT and track dirtiness when receiving a memory fault doing a write.

```c++
HRESULT
WhvBackend_t::OnExitReasonMemoryAccess(
    const WHV_RUN_VP_EXIT_CONTEXT &Exception) {
  const Gpa_t Gpa = Gpa_t(Exception.MemoryAccess.Gpa);
  const bool WriteAccess =
      Exception.MemoryAccess.AccessInfo.AccessType == WHvMemoryAccessWrite;

  if (!WriteAccess) {
    fmt::print("Dont know how to handle this fault, exiting.\n");
    __debugbreak();
    return E_FAIL;
  }

  //
  // Remap the page as writeable.
  //

  const WHV_MAP_GPA_RANGE_FLAGS Flags = WHvMapGpaRangeFlagWrite |
                                        WHvMapGpaRangeFlagRead |
                                        WHvMapGpaRangeFlagExecute;

  const Gpa_t AlignedGpa = Gpa.Align();
  DirtyGpa(AlignedGpa);

  uint8_t *AlignedHva = PhysTranslate(AlignedGpa);
  return MapGpaRange(AlignedHva, AlignedGpa, Page::Size, Flags);
}
```

Once fixed, I noticed that [WHvTranslateGva](https://docs.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvtranslategva) also was slower than I  expected. This is why I also emulated its behavior by walking the page tables myself:

```c++
HRESULT
WhvBackend_t::TranslateGva(const Gva_t Gva, const WHV_TRANSLATE_GVA_FLAGS,
                           WHV_TRANSLATE_GVA_RESULT &TranslationResult,
                           Gpa_t &Gpa) const {

  //
  // Stole most of the logic from @yrp604's code so thx bro.
  //

  const VIRTUAL_ADDRESS GuestAddress = Gva.U64();
  const MMPTE_HARDWARE Pml4 = GetReg64(WHvX64RegisterCr3);
  const uint64_t Pml4Base = Pml4.PageFrameNumber * Page::Size;
  const Gpa_t Pml4eGpa = Gpa_t(Pml4Base + GuestAddress.Pml4Index * 8);
  const MMPTE_HARDWARE Pml4e = PhysRead8(Pml4eGpa);
  if (!Pml4e.Present) {
    TranslationResult.ResultCode = WHvTranslateGvaResultPageNotPresent;
    return S_OK;
  }

  const uint64_t PdptBase = Pml4e.PageFrameNumber * Page::Size;
  const Gpa_t PdpteGpa = Gpa_t(PdptBase + GuestAddress.PdPtIndex * 8);
  const MMPTE_HARDWARE Pdpte = PhysRead8(PdpteGpa);
  if (!Pdpte.Present) {
    TranslationResult.ResultCode = WHvTranslateGvaResultPageNotPresent;
    return S_OK;
  }

  //
  // huge pages:
  // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
  // directory; see Table 4-1
  //

  const uint64_t PdBase = Pdpte.PageFrameNumber * Page::Size;
  if (Pdpte.LargePage) {
    TranslationResult.ResultCode = WHvTranslateGvaResultSuccess;
    Gpa = Gpa_t(PdBase + (Gva.U64() & 0x3fff'ffff));
    return S_OK;
  }

  const Gpa_t PdeGpa = Gpa_t(PdBase + GuestAddress.PdIndex * 8);
  const MMPTE_HARDWARE Pde = PhysRead8(PdeGpa);
  if (!Pde.Present) {
    TranslationResult.ResultCode = WHvTranslateGvaResultPageNotPresent;
    return S_OK;
  }

  //
  // large pages:
  // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
  // table; see Table 4-18
  //

  const uint64_t PtBase = Pde.PageFrameNumber * Page::Size;
  if (Pde.LargePage) {
    TranslationResult.ResultCode = WHvTranslateGvaResultSuccess;
    Gpa = Gpa_t(PtBase + (Gva.U64() & 0x1f'ffff));
    return S_OK;
  }

  const Gpa_t PteGpa = Gpa_t(PtBase + GuestAddress.PtIndex * 8);
  const MMPTE_HARDWARE Pte = PhysRead8(PteGpa);
  if (!Pte.Present) {
    TranslationResult.ResultCode = WHvTranslateGvaResultPageNotPresent;
    return S_OK;
  }

  TranslationResult.ResultCode = WHvTranslateGvaResultSuccess;
  const uint64_t PageBase = Pte.PageFrameNumber * 0x1000;
  Gpa = Gpa_t(PageBase + GuestAddress.Offset);
  return S_OK;
}
```

**Collecting dividends**

Comparing the two backends, whv showed about 15x better performance over bochscpu. I honestly was a bit disappointed as I expected more of a 100x performance increase but I guess it was still a significant perf increase:

```
bochscpu:
#1 cov: 260546 corp: 0 exec/s: 0.1 lastcov: 0.0s crash: 0 timeout: 0 cr3: 0
#2 cov: 260546 corp: 0 exec/s: 0.1 lastcov: 12.0s crash: 0 timeout: 0 cr3: 0
#3 cov: 260546 corp: 0 exec/s: 0.1 lastcov: 25.0s crash: 0 timeout: 0 cr3: 0
#4 cov: 260546 corp: 0 exec/s: 0.1 lastcov: 38.0s crash: 0 timeout: 0 cr3: 0

whv:
#12 cov: 25521 corp: 0 exec/s: 1.5 lastcov: 6.0s crash: 0 timeout: 0 cr3: 0
#30 cov: 25521 corp: 0 exec/s: 1.5 lastcov: 16.0s crash: 0 timeout: 0 cr3: 0
#48 cov: 25521 corp: 0 exec/s: 1.5 lastcov: 27.0s crash: 0 timeout: 0 cr3: 0
#66 cov: 25521 corp: 0 exec/s: 1.5 lastcov: 37.0s crash: 0 timeout: 0 cr3: 0
#84 cov: 25521 corp: 0 exec/s: 1.5 lastcov: 47.0s crash: 0 timeout: 0 cr3: 0
```

The speed started to be good enough for me to run it overnight and discover my first few crashes which was exciting even though they were just `interr`.

# 2 fast 2 furious: KVM backend

I really wanted to start fuzzing IDA on some proper hardware. It was pretty clear that renting Windows machines in the cloud with nested virtualization enabled wasn't something widespread or cheap. On top of that, I was still disappointed by the performance of whv and so I was eager to see how battle-tested hypervisors like Xen or KVM would measure.

I didn't know anything about those VMM but I quickly discovered that KVM was available in the Linux kernel and that it exposed a user-mode API that resembled whv via `/dev/kvm`. This looked perfect because if it was similar enough to whv I could probably write a backend for it easily. The [KVM API](https://www.kernel.org/doc/html/latest/virt/kvm/api.html) powers [Firecracker](https://firecracker-microvm.github.io/) that is a project creating micro vms to run various workloads in the cloud. I assumed that you would need rich features as well as good performance to be the foundation technology of this project.

KVM APIs worked very similarly to whv and as a result, I will not repeat the previous part. Instead, I will just walk you through some of the differences and things I enjoyed more with KVM.

**GPRs available through shared-memory**

To avoid sending an IOCTL every time you want the value of the guest GPR, KVM allows you to map a shared memory region with the kernel where the registers are laid out:

```C++
//
// Get the size of the shared kvm run structure.
//

VpMmapSize_ = ioctl(Kvm_, KVM_GET_VCPU_MMAP_SIZE, 0);
if (VpMmapSize_ < 0) {
  perror("Could not get the size of the shared memory region.");
  return false;
}

//
// Man says:
//   there is an implicit parameter block that can be obtained by mmap()'ing
//   the vcpu fd at offset 0, with the size given by KVM_GET_VCPU_MMAP_SIZE.
//

Run_ = (struct kvm_run *)mmap(nullptr, VpMmapSize_, PROT_READ | PROT_WRITE,
                              MAP_SHARED, Vp_, 0);
if (Run_ == nullptr) {
  perror("mmap VCPU_MMAP_SIZE");
  return false;
}
```

**On-demand paging**

Implementing on demand paging with KVM was very easy. It uses [userfaultfd](https://www.kernel.org/doc/html/latest/admin-guide/mm/userfaultfd.html) and so you can just start a thread that polls and that services the requests:

```C++
void KvmBackend_t::UffdThreadMain() {
  while (!UffdThreadStop_) {

    //
    // Set up the pool fd with the uffd fd.
    //

    struct pollfd PoolFd = {.fd = Uffd_, .events = POLLIN};

    int Res = poll(&PoolFd, 1, 6000);
    if (Res < 0) {

      //
      // Sometimes poll returns -EINTR when we are trying to kick off the CPU
      // out of KVM_RUN.
      //

      if (errno == EINTR) {
        fmt::print("Poll returned EINTR\n");
        continue;
      }

      perror("poll");
      exit(EXIT_FAILURE);
    }

    //
    // This is the timeout, so we loop around to have a chance to check for
    // UffdThreadStop_.
    //

    if (Res == 0) {
      continue;
    }

    //
    // You get the address of the access that triggered the missing page event
    // out of a struct uffd_msg that you read in the thread from the uffd. You
    // can supply as many pages as you want with UFFDIO_COPY or UFFDIO_ZEROPAGE.
    // Keep in mind that unless you used DONTWAKE then the first of any of those
    // IOCTLs wakes up the faulting thread.
    //

    struct uffd_msg UffdMsg;
    Res = read(Uffd_, &UffdMsg, sizeof(UffdMsg));
    if (Res < 0) {
      perror("read");
      exit(EXIT_FAILURE);
    }

    //
    // Let's ensure we are dealing with what we think we are dealing with.
    //

    if (Res != sizeof(UffdMsg) || UffdMsg.event != UFFD_EVENT_PAGEFAULT) {
      fmt::print("The uffdmsg or the type of event we received is unexpected, "
                 "bailing.");
      exit(EXIT_FAILURE);
    }

    //
    // Grab the HVA off the message.
    //

    const uint64_t Hva = UffdMsg.arg.pagefault.address;

    //
    // Compute the GPA from the HVA.
    //

    const Gpa_t Gpa = Gpa_t(Hva - uint64_t(Ram_.Hva()));

    //
    // Page it in.
    //

    RunStats_.UffdPages++;
    const uint8_t *Src = Ram_.GetHvaFromDump(Gpa);
    if (Src != nullptr) {
      const struct uffdio_copy UffdioCopy = {
          .dst = Hva,
          .src = uint64_t(Src),
          .len = Page::Size,
      };

      //
      // The primary ioctl to resolve userfaults is UFFDIO_COPY. That atomically
      // copies a page into the userfault registered range and wakes up the
      // blocked userfaults (unless uffdio_copy.mode & UFFDIO_COPY_MODE_DONTWAKE
      // is set). Other ioctl works similarly to UFFDIO_COPY. They’re atomic as
      // in guaranteeing that nothing can see an half copied page since it’ll
      // keep userfaulting until the copy has finished.
      //

      Res = ioctl(Uffd_, UFFDIO_COPY, &UffdioCopy);
      if (Res < 0) {
        perror("UFFDIO_COPY");
        exit(EXIT_FAILURE);
      }
    } else {
      const struct uffdio_zeropage UffdioZeroPage = {
          .range = {.start = Hva, .len = Page::Size}};

      Res = ioctl(Uffd_, UFFDIO_ZEROPAGE, &UffdioZeroPage);
      if (Res < 0) {
        perror("UFFDIO_ZEROPAGE");
        exit(EXIT_FAILURE);
      }
    }
  }
}
```

**Timeout**

Another cool thing is that KVM exposes the Performance Monitoring Unit to the guests if the hardware supports it. When the hardware supports it, I am able to program the PMU to trigger an interruption after an arbitrary number of retired instructions. This is useful because when `MSR_IA32_FIXED_CTR0` overflows, it triggers a special interruption called a PMI that gets delivered via the vector 0xE of the CPU's IDT. To catch it, we simply break on `hal!HalPerfInterrupt`:

```C++
//
// This is to catch the PMI interrupt if performance counters are used to
// bound execution.
//

if (!g_Backend->SetBreakpoint("hal!HalpPerfInterrupt",
                              [](Backend_t *Backend) {
                                CrashDetectionPrint("Perf interrupt\n");
                                Backend->Stop(Timedout_t());
                              })) {
  fmt::print("Could not set a breakpoint on hal!HalpPerfInterrupt, but "
              "carrying on..\n");
}
```

To make it work you have to program the APIC a little bit and I remember struggling to get the interruption fired. I am still not 100% sure that I got the details fully right but the interruption triggered consistently during my tests and so I called it a day. I would also like to revisit this area in the future as there might be other features I could use for the fuzzer.

**Problem 9: Running it in the cloud**

The KVM backend development was done on a laptop in a Hyper-V VM with nested virtualization on. It worked great but it was not powerful and so I wanted to run it on real hardware. After shopping around, I realized that Amazon didn't have any offers that supported nested virtualization and that only Microsoft's Azure had available SKUs with nested virtualization on. I rented one of them to try it out and the hardware didn't support this VMX feature called [unrestricted_guest](https://patchwork.kernel.org/project/kvm/patch/1243552292.25456.23.camel@mukti.sc.intel.com/). I can't quite remember why it mattered but it had to do with real mode & the APIC and the way I create memory slots. I had developed the backend assuming this feature would be here and so I didn't use Azure either.

Instead, I rented a bare-metal server on [vultr](https://www.vultr.com/products/bare-metal/) for about 100$ / mo. The CPU was a Xeon E3-1270v6 processor, 4 cores, 8 threads @ 3.8GHz which seemed good enough for my usage. The hardware had a PMU and that is where I developed the support for it in wtf as well.

I was pretty happy because the fuzzer was running about 10x faster than whv. It is not a fair comparison because those numbers weren't acquired from the same hardware but still:

```text
#123 cov: 25521 corp: 0 exec/s: 12.3 lastcov: 9.0s crash: 0 timeout: 0 cr3: 0
#252 cov: 25521 corp: 0 exec/s: 12.5 lastcov: 19.0s crash: 0 timeout: 0 cr3: 0
#381 cov: 25521 corp: 0 exec/s: 12.5 lastcov: 29.0s crash: 0 timeout: 0 cr3: 0
#510 cov: 25521 corp: 0 exec/s: 12.6 lastcov: 39.0s crash: 0 timeout: 0 cr3: 0
#639 cov: 25521 corp: 0 exec/s: 12.6 lastcov: 49.0s crash: 0 timeout: 0 cr3: 0
#768 cov: 25521 corp: 0 exec/s: 12.6 lastcov: 59.0s crash: 0 timeout: 0 cr3: 0
#897 cov: 25521 corp: 0 exec/s: 12.6 lastcov: 1.1min crash: 0 timeout: 0 cr3: 0
```

To give you more details, this test case used generated executions of around 195 millions instructions with the following stats (generated by bochscpu):

```text
Run stats:
Instructions executed: 194593453 (260546 unique)
          Dirty pages: 9166848 bytes (0 MB)
      Memory accesses: 411196757 bytes (24 MB)
```

**Problem 10: Minsetting a 1.6m files corpus**

In parallel with coding wtf, I acquired a fairly large corpus made of the weirdest ELF possible. I built this corpus made of 1.6 million ELF files and I now needed to minset it. Because of the way I had architected wtf, minsetting was a serial process. I could have gone the AFL route and generate execution traces that eventually get merged together but I didn't like this idea either.

Instead, I re-architected wtf into a client and a server. The server owns the coverage, the corpus, and the mutator. It just distributes test cases to clients and receives code coverage reports from them. You can see the clients are runners that send back results to the server. All the important state is kept in the server.

This model was nice because it automatically meant that I could fully utilize the hardware I was renting to minset those files. As an example, minsetting this corpus of files with a single core would have probably taken weeks to complete but it took 8 hours with this new architecture:

```text
#1972714 cov: 74065 corp: 3176 (58mb) exec/s: 64.2 (8 nodes) lastcov: 3.0s crash: 49 timeout: 71 cr3: 48 uptime: 8hr
```

# Wrapping up

In this post we went through the birth of [wtf](https://github.com/0vercl0k/wtf) which is a distributed, code-coverage guided, customizable, cross-platform snapshot-based fuzzer designed for attacking user and/or kernel-mode targets running on Microsoft Windows. It also led to writing and open-sourcing a number of other small projects: [lockmem](https://github.com/0vercl0k/lockmem), [inject](https://github.com/0vercl0k/lockmem), [kdmp-parser](https://github.com/0vercl0k/kdmp-parser) and [symbolizer](https://github.com/0vercl0k/symbolizer).

We went from zero to dozens of unique crashes in various IDA components:  `libdwarf64.dll`, `dwarf64.dll`, `elf64.dll` and `pdb64.dll`. The findings were really diverse: null-dereference, stack-overflows, division by zero, infinite loops, use-after-frees, and out-of-bounds accesses. I have compiled all of my findings in the following Github repository: [fuzzing-ida75](https://github.com/0vercl0k/fuzzing-ida75).

<center>![bounty.png](/images/fuzzing_ida/bounty.png)</center>

I probably fuzzed for an entire month but most of the crashes popped up in the first two weeks. According to [lighthouse](https://github.com/gaasedelen/lighthouse), I managed to cover about 80% of `elf64.dll`, 50% of `dwarf64.dll` and 26% of `libdwarf64.dll` with a minset of about 2.4k files for a total of 17MB.

<center>![elf64.png](/images/fuzzing_ida/elf64.png)</center>

Before signing out, I wanted to thank the [IDA Hex-Rays](https://hex-rays.com/IDA-pro/) team for handling & fixing my reports at an amazing speed. I would highly recommend for you to try out their bounty as I am sure there's a lot to be found.

Finally big up to my bros [yrp604](https://twitter.com/yrp604) & [__x86](https://twitter.com/__x86) for proofreading this article.
