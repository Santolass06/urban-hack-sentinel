"""
HID Module - Human Interface Device support.

Provides:
- DuckyScript parser and encoder (Hack5 DuckyScript v1/v3)
- USB Gadget manager (ConfigFS)
- HID Injector (uinput/usb-gadget)
"""

from urban_hs.modules.hid.ducky import (
    LAYOUT_DE,
    LAYOUT_ES,
    LAYOUT_FR,
    LAYOUT_GB,
    LAYOUT_IT,
    LAYOUT_RU,
    LAYOUT_US,
    DuckyCommand,
    DuckyCommandType,
    DuckyCompiler,
    DuckyEncoder,
    DuckyParser,
    KeyboardLayout,
    KeyMapper,
    ParsedScript,
    create_compiler,
    load_ducky_file,
)
from urban_hs.modules.hid.gadget import (
    GadgetConfig,
    GadgetFunction,
    GadgetSpeed,
    HIDConfig,
    HIDReportDescriptors,
    MassStorageConfig,
    NetworkConfig,
    SerialConfig,
    USBGadgetManager,
)
from urban_hs.modules.hid.injector import (
    HIDInjector,
    InjectionConfig,
    InjectionEvent,
    InjectionMode,
    InjectionReport,
    InjectionStatus,
    UInputInjector,
    USBGadgetInjector,
    quick_ducky,
    quick_type,
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