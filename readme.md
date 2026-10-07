# tsschecker

tsschecker is a powerful tool to check TSS signing status on combinations of various apple devices and firmware versions.

## Features  
* Supports: Apple TV, Apple Watch, HomePod, iPad, iPhone, iPod touch, M1 Macs and the T2 Coprocessor.
* Allows you to get lists of supported apple devices as well as Firmwares and OTA versions for any specified apple device.
* Can check signing status for any firmware version by specifying either a firmware version or a BuildManifest.
* Works without specifying any device relevant values to check signing status, but can be used to save blobs when given an ECID and the option --print-tss-response (although there are better tools to do this).

tsschecker is not only meant to be used to check firmware signing status, but also to explore Apple's TSS servers.<br/>
By using all of its customization possibilities, you might discover a combination of devices and firmware versions that is getting signed but wasn't getting signed before. 

```
.\tsschecker.exe -h                                                                                          
Usage of tsschecker.exe:
  -device string
        Device product type (for example, iPhone11,6)
  -ecid string
        ECID of the device
  -ipsw string
        Path to the IPSW file
```

## Thanks
https://github.com/1Conan/tsschecker
