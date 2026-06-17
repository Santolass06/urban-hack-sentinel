"""
HID Module - Human Interface Device support.

Provides:
- DuckyScript parser and encoder (Hack5 DuckyScript v1/v3)
- USB Gadget manager (ConfigFS)
- HID Injector (uinput/usb-gadget)
"""

from urban_hs.modules.hid.gadget import (
    GadgetFunction,
    GadgetSpeed,
    GadgetConfig,
    HIDConfig,
    MassStorageConfig,
    NetworkConfig,
    SerialConfig,
    USBGadgetManager,
    HIDReportDescriptors,
)

from urban_hs.modules.hid.ducky import (
    KeyboardLayout,
    DuckyCommandType,
    DuckyCommand,
    ParsedScript,
    KeyMapper,
    DuckyParser,
    DuckyEncoder,
    DuckyCompiler,
    LAYOUT_US,
    LAYOUT_GB,
    LAYOUT_DE,
    LAYOUT_FR,
    LAYOUT_ES,
    LAYOUT_IT,
    LAYOUT_RU,
    create_compiler,
    load_ducky_file,
)

from urban_hs.modules.hid.injector import (
    InjectionMode,
    InjectionStatus,
    InjectionConfig,
    InjectionEvent,
    InjectionReport,
    UInputInjector,
    USBGadgetInjector,
    HIDInjector,
    quick_type,
    quick_ducky,
)

__all__ = [
    # DuckyScript
    "KeyboardLayout",
    "DuckyCommandType",
    "DuckyCommand",
    "ParsedScript",
    "KeyMapper",
    "DuckyParser",
    "DuckyEncoder",
    "DuckyCompiler",
    "LAYOUT_US",
    "LAYOUT_GB",
    "LAYOUT_DE",
    "LAYOUT_FR",
    "LAYOUT_ES",
    "LAYOUT_IT",
    "LAYOUT_RU",
    "create_compiler",
    "load_ducky_file",
    # USB Gadget
    "GadgetFunction",
    "GadgetSpeed",
    "GadgetConfig",
    "HIDConfig",
    "MassStorageConfig",
    "NetworkConfig",
    "SerialConfig",
    "USBGadgetManager",
    "HIDReportDescriptors",
    # HID Injector
    "InjectionMode",
    "InjectionStatus",
    "InjectionConfig",
    "InjectionEvent",
    "InjectionReport",
    "UInputInjector",
    "USBGadgetInjector",
    "HIDInjector",
    "quick_type",
    "quick_ducky",
]