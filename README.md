# NICPROV
Prototype source code for NICPROV

## Required MACHINE 
NICPROV requires two machines---secure hardware device and host machine---connected through PCIE-4.0 interface.

We use BLUEFIELD-2, a commercial data processing unit (DPU) product, as our secure hardware. BLUEFIELD-2 integrates a dual-port 200Gb/s InfiniBand network adapter, a 16-lane PCIe Gen4.0 switch, and eight 64-bit Armv8 A72 cores on a single chip.
It has 16 GB of onboard DDR4 memory, 64 GB of eMMC memory, and a powerful DMA engine.

To create applications and services for BLUEFIELD-2, you should install a development kit, DOCA, on the host mahcnine first. The install procedures are as follows: https://docs.nvidia.com/doca/sdk/nvidia+doca+installation+guide+for+linux/index.html
