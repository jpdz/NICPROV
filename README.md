# NICPROV
Prototype source code for NICPROV

## Required MACHINE 
NICPROV requires two machines---secure hardware device and host machine---connected through PCIE-4.0 interface.

We use NVIDIA BLUEFIELD-2, a commercial data processing unit (DPU) product, as our secure hardware. BLUEFIELD-2 integrates a 16-lane PCIe Gen4.0 switch, and eight 64-bit Armv8 A72 cores on a single chip. It has 16 GB of onboard DDR4 memory, 64 GB of eMMC memory, and a powerful DMA engine.

### Pre-requisites
To effectively use BLUEFIELD-2, you should install a development kit, DOCA, on the host mahcnine. The install procedures are as follows: https://docs.nvidia.com/doca/sdk/nvidia+doca+installation+guide+for+linux/index.html#src-2654401500_id-.NVIDIADOCAInstallationGuideforLinuxv2.7.0-InstallingSoftwareonHost

Please also make sure the full DOCA image on BlueField-2 is upgraded as follows: https://docs.nvidia.com/doca/sdk/nvidia+doca+installation+guide+for+linux/index.html#src-2654401500_id-.NVIDIADOCAInstallationGuideforLinuxv2.7.0-InstallingSoftwareonDPU

### Installation Instructions
For host machine, you should compile and install the kernel module first
```shell
make driver
sudo insmod scap.ko
```
For device, the project is constructed by meson, you can find a executable file called 'doca_dma_copy' in project build directory.
```device shell
meson build
ninja -C build
```

