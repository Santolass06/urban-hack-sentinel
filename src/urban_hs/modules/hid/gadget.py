"""
USB Gadget Manager - ConfigFS USB Gadget Profiles.

Manages Linux USB gadget subsystem via ConfigFS for:
- HID keyboard/mouse
- Mass Storage (IMG/ISO mount)
- RNDIS/ECM/ACM (Network)
- ACM (Serial)
- VID/PID/Serial customization
- Composite devices
"""

import asyncio
import os
import structlog
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Union

logger = structlog.get_logger(__name__)


class GadgetFunction(Enum):
    """USB gadget function types."""
    HID = "hid"                    # Human Interface Device
    MASS_STORAGE = "mass_storage"  # Mass Storage
    RNDIS = "rndis"                # USB Ethernet/RNDIS
    ECM = "ecm"                    # Ethernet Control Model
    ACM = "acm"                    # Abstract Control Model (Serial)
    NCM = "ncm"                    # Network Control Model
    MIDI = "midi"                  # MIDI
    PRINTER = "printer"            # Printer
    AUDIO_SOURCE = "audio_source"  # Audio Source
    AUDIO_SINK = "audio_sink"      # Audio Sink


class GadgetSpeed(Enum):
    """USB speeds."""
    LOW = "low"           # 1.5 Mbps
    FULL = "full"         # 12 Mbps
    HIGH = "high"         # 480 Mbps
    SUPER = "super"       # 5 Gbps
    SUPER_PLUS = "super_plus"  # 10 Gbps


@dataclass
class GadgetConfig:
    """USB Gadget configuration."""
    # Device identification
    vendor_id: str = "0x1d6b"       # Linux Foundation
    product_id: str = "0x0104"      # Gadget
    device_version: str = "0x0100"  # v1.00
    usb_version: str = "0x0200"     # USB 2.0
    
    # Strings
    manufacturer: str = "Urban Hack Sentinel"
    product: str = "USB Gadget"
    serial_number: str = "000000000001"
    
    # Power
    max_power: int = 500  # mA
    self_powered: bool = False
    remote_wakeup: bool = False
    
    # Functions
    functions: List[GadgetFunction] = field(default_factory=list)
    
    # ConfigFS paths
    configfs_root: str = "/sys/kernel/config/usb_gadget"
    gadget_name: str = "urban_hs"


@dataclass
class HIDConfig:
    """HID function configuration."""
    protocol: int = 1           # 1=Keyboard, 2=Mouse
    subclass: int = 1           # 1=Boot interface
    report_length: int = 8      # Report length
    report_desc: Optional[bytes] = None  # Custom report descriptor


@dataclass
class MassStorageConfig:
    """Mass Storage function configuration."""
    file_path: str = ""         # Backing file path
    block_size: int = 512       # Block size
    num_blocks: int = 0         # Number of blocks (0 = auto)
    read_only: bool = False     # Read only
    removable: bool = True      # Removable media
    cdrom: bool = False         # CD-ROM emulation
    stall: bool = False         # Stall support


@dataclass
class NetworkConfig:
    """Network function (RNDIS/ECM/NCM) configuration."""
    host_addr: str = "00:11:22:33:44:55"  # Host MAC
    dev_addr: str = "00:11:22:33:44:56"   # Device MAC
    host_ip: str = "192.168.7.1"
    dev_ip: str = "192.168.7.2"
    netmask: str = "255.255.255.0"


@dataclass
class SerialConfig:
    """Serial (ACM) function configuration."""
    port: int = 0  # 0 = auto


class USBGadgetManager:
    """
    Manages Linux USB gadget subsystem via ConfigFS.
    
    Features:
    - Create/destroy gadgets
    - Add/remove functions (HID, Mass Storage, Network, Serial)
    - Configure VID/PID/serial strings
    - Composite devices
    - Persistent configurations
    """
    
    def __init__(self, config: Optional[GadgetConfig] = None):
        self.config = config or GadgetConfig()
        self.gadget_path = Path(self.config.configfs_root) / self.config.gadget_name
        self._active = False
        self._functions_loaded: Dict[GadgetFunction, bool] = {}
        self._function_configs: Dict[GadgetFunction, Any] = {}
    
    def is_available(self) -> bool:
        """Check if USB gadget subsystem is available."""
        return (
            Path("/sys/kernel/config/usb_gadget").exists() and
            Path("/sys/class/udc").exists()
        )
    
    def get_udc_controllers(self) -> List[str]:
        """Get available UDC (USB Device Controller) controllers."""
        udc_path = Path("/sys/class/udc")
        if udc_path.exists():
            return [d.name for d in udc_path.iterdir() if d.is_dir()]
        return []
    
    def create_gadget(self, config: Optional[GadgetConfig] = None) -> bool:
        """Create USB gadget in ConfigFS."""
        if config:
            self.config = config
        
        if not self.is_available():
            logger.error("USB gadget subsystem not available")
            return False
        
        try:
            gadget_path = Path(self.config.configfs_root) / self.config.gadget_name
            
            # Create gadget directory
            gadget_path.mkdir(parents=True, exist_ok=True)
            
            # Write device descriptors
            self._write_descriptor(gadget_path / "idVendor", self.config.vendor_id)
            self._write_descriptor(gadget_path / "idProduct", self.config.product_id)
            self._write_descriptor(gadget_path / "bcdDevice", self.config.device_version)
            self._write_descriptor(gadget_path / "bcdUSB", self.config.usb_version)
            
            # Strings
            strings_dir = gadget_path / "strings" / "0x409"  # English
            strings_dir.mkdir(parents=True, exist_ok=True)
            self._write_descriptor(strings_dir / "manufacturer", self.config.manufacturer)
            self._write_descriptor(strings_dir / "product", self.config.product)
            self._write_descriptor(strings_dir / "serialnumber", self.config.serial_number)
            
            # Config
            config_dir = gadget_path / "configs" / "c.1"
            config_dir.mkdir(parents=True, exist_ok=True)
            self._write_descriptor(config_dir / "MaxPower", str(self.config.max_power))
            
            # Config strings
            config_strings = config_dir / "strings" / "0x409"
            config_strings.mkdir(parents=True, exist_ok=True)
            self._write_descriptor(config_strings / "configuration", "USB Gadget Config")
            
            self._active = True
            logger.info("Gadget created", path=str(gadget_path))
            return True
            
        except Exception as e:
            logger.error("Failed to create gadget", error=str(e))
            return False
    
    def _write_descriptor(self, path: Path, value: str):
        """Write value to ConfigFS descriptor."""
        try:
            path.write_text(value)
        except Exception as e:
            logger.error("Failed to write descriptor", path=str(path), error=str(e))
            raise
    
    def add_hid_function(self, config: Optional[HIDConfig] = None, instance: int = 0) -> bool:
        """Add HID function to gadget."""
        if not self.ensure_gadget():
            return False
        
        try:
            func_dir = self.gadget_path / "functions" / f"hid.{instance}"
            func_dir.mkdir(parents=True, exist_ok=True)
            
            hid_config = config or HIDConfig()
            self._function_configs[GadgetFunction.HID] = hid_config
            
            # Write HID descriptors
            self._write_descriptor(func_dir / "protocol", str(hid_config.protocol))
            self._write_descriptor(func_dir / "subclass", str(hid_config.subclass))
            self._write_descriptor(func_dir / "report_length", str(hid_config.report_length))
            
            if hid_config.report_desc:
                with open(func_dir / "report_desc", "wb") as f:
                    f.write(hid_config.report_desc)
            
            self._functions_loaded[GadgetFunction.HID] = True
            logger.info("HID function added", instance=instance)
            return True
            
        except Exception as e:
            logger.error("Failed to add HID function", error=str(e))
            return False
    
    def add_mass_storage_function(self, config: MassStorageConfig, instance: int = 0) -> bool:
        """Add Mass Storage function to gadget."""
        if not self.ensure_gadget():
            return False
        
        try:
            func_dir = self.gadget_path / "functions" / f"mass_storage.{instance}"
            func_dir.mkdir(parents=True, exist_ok=True)
            
            self._function_configs[GadgetFunction.MASS_STORAGE] = config
            
            # Write Mass Storage descriptors
            self._write_descriptor(func_dir / "file", config.file_path)
            if config.block_size:
                self._write_descriptor(func_dir / "block_size", str(config.block_size))
            if config.num_blocks:
                self._write_descriptor(func_dir / "num_blocks", str(config.num_blocks))
            self._write_descriptor(func_dir / "ro", "1" if config.read_only else "0")
            self._write_descriptor(func_dir / "removable", "1" if config.removable else "0")
            self._write_descriptor(func_dir / "cdrom", "1" if config.cdrom else "0")
            self._write_descriptor(func_dir / "stall", "1" if config.stall else "0")
            
            # Calculate blocks if not specified
            if config.num_blocks == 0 and config.file_path:
                file_size = Path(config.file_path).stat().st_size
                num_blocks = file_size // config.block_size
                self._write_descriptor(func_dir / "num_blocks", str(num_blocks))
            
            self._functions_loaded[GadgetFunction.MASS_STORAGE] = True
            logger.info("Mass Storage function added", instance=instance, file=config.file_path)
            return True
            
        except Exception as e:
            logger.error("Failed to add Mass Storage function", error=str(e))
            return False
    
    def add_network_function(self, function_type: GadgetFunction, config: NetworkConfig, instance: int = 0) -> bool:
        """Add network function (RNDIS/ECM/NCM) to gadget."""
        if function_type not in (GadgetFunction.RNDIS, GadgetFunction.ECM, GadgetFunction.NCM):
            logger.error("Invalid network function type", type=function_type.value)
            return False
        
        if not self.ensure_gadget():
            return False
        
        try:
            func_dir = self.gadget_path / "functions" / f"{function_type.value}.{instance}"
            func_dir.mkdir(parents=True, exist_ok=True)
            
            self._function_configs[function_type] = config
            
            # Write network descriptors
            self._write_descriptor(func_dir / "host_addr", config.host_addr)
            self._write_descriptor(func_dir / "dev_addr", config.dev_addr)
            
            self._functions_loaded[function_type] = True
            logger.info("Network function added", type=function_type.value, instance=instance)
            return True
            
        except Exception as e:
            logger.error("Failed to add network function", error=str(e))
            return False
    
    def add_serial_function(self, config: Optional[SerialConfig] = None, instance: int = 0) -> bool:
        """Add ACM (Serial) function to gadget."""
        if not self.ensure_gadget():
            return False
        
        try:
            func_dir = self.gadget_path / "functions" / f"acm.{instance}"
            func_dir.mkdir(parents=True, exist_ok=True)
            
            serial_config = config or SerialConfig()
            self._function_configs[GadgetFunction.ACM] = serial_config
            
            # No special descriptors needed for ACM
            self._functions_loaded[GadgetFunction.ACM] = True
            logger.info("Serial function added", instance=instance)
            return True
            
        except Exception as e:
            logger.error("Failed to add serial function", error=str(e))
            return False
    
    def ensure_gadget(self) -> bool:
        """Ensure gadget exists, create if needed."""
        if not self._active:
            return self.create_gadget()
        return True
    
    def bind_udc(self, udc: Optional[str] = None) -> bool:
        """Bind gadget to UDC controller."""
        if not self._active:
            logger.error("Gadget not active")
            return False
        
        udc_controllers = self.get_udc_controllers()
        if not udc_controllers:
            logger.error("No UDC controllers available")
            return False
        
        target_udc = udc or udc_controllers[0]
        
        try:
            udc_path = Path("/sys/class/udc") / target_udc
            if not udc_path.exists():
                logger.error("UDC not found", udc=target_udc)
                return False
            
            bind_path = self.gadget_path / "UDC"
            self._write_descriptor(bind_path, target_udc)
            
            logger.info("Gadget bound to UDC", udc=target_udc)
            return True
            
        except Exception as e:
            logger.error("Failed to bind UDC", error=str(e))
            return False
    
    def unbind_udc(self) -> bool:
        """Unbind gadget from UDC controller."""
        if not self._active:
            return True
        
        try:
            bind_path = self.gadget_path / "UDC"
            if bind_path.exists():
                # Read current UDC before unbinding
                current_udc = bind_path.read_text().strip()
                self._write_descriptor(bind_path, "")
                logger.info("Gadget unbound from UDC", udc=current_udc)
            return True
        except Exception as e:
            logger.error("Failed to unbind UDC", error=str(e))
            return False
    
    def add_function_to_config(self, func_type: GadgetFunction, instance: int = 0) -> bool:
        """Link function to configuration."""
        if not self._active:
            return False
        
        try:
            func_name = f"{func_type.value}.{instance}"
            config_dir = self.gadget_path / "configs" / "c.1"
            link_path = config_dir / func_name
            func_path = self.gadget_path / "functions" / func_name
            
            if link_path.exists():
                logger.warning("Function already linked", func=func_name)
                return True
            
            if not func_path.exists():
                logger.error("Function not found", func=func_name)
                return False
            
            link_path.symlink_to(func_path)
            logger.info("Function linked to config", func=func_name)
            return True
            
        except Exception as e:
            logger.error("Failed to link function", func=func_name, error=str(e))
            return False
    
    def remove_function(self, func_type: GadgetFunction, instance: int = 0) -> bool:
        """Remove function from gadget."""
        try:
            # Unlink from config
            func_name = f"{func_type.value}.{instance}"
            config_dir = self.gadget_path / "configs" / "c.1"
            link_path = config_dir / func_name
            if link_path.exists():
                link_path.unlink()
            
            # Remove function directory
            func_path = self.gadget_path / "functions" / func_name
            if func_path.exists():
                # Remove function (will fail if still linked)
                import shutil
                shutil.rmtree(func_path)
            
            self._functions_loaded.pop(func_type, None)
            logger.info("Function removed", func=func_name)
            return True
            
        except Exception as e:
            logger.error("Failed to remove function", func=func_name, error=str(e))
            return False
    
    def destroy_gadget(self) -> bool:
        """Destroy gadget and clean up ConfigFS."""
        try:
            # Unbind UDC first
            if self._active:
                self.unbind_udc()
            
            # Remove all functions
            for func_type in list(self._functions_loaded.keys()):
                self.remove_function(func_type)
            
            # Remove configs
            for config_dir in (self.gadget_path / "configs").iterdir():
                if config_dir.is_dir():
                    import shutil
                    shutil.rmtree(config_dir)
            
            # Remove strings
            import shutil
            strings_dir = self.gadget_path / "strings"
            if strings_dir.exists():
                shutil.rmtree(strings_dir)
            
            # Remove functions
            func_dir = self.gadget_path / "functions"
            if func_dir.exists():
                shutil.rmtree(func_dir)
            
            # Remove gadget
            if self.gadget_path.exists():
                shutil.rmtree(self.gadget_path)
            
            self._active = False
            logger.info("Gadget destroyed")
            return True
            
        except Exception as e:
            logger.error("Failed to destroy gadget", error=str(e))
            return False
    
    # Quick setup methods
    def setup_hid_keyboard(self, report_desc: Optional[bytes] = None) -> bool:
        """Quick setup for HID keyboard."""
        if not self.ensure_gadget():
            return False
        
        success = self.add_hid_function(HIDConfig(
            protocol=1,  # Keyboard
            subclass=1,
            report_length=8,
            report_desc=report_desc
        ))
        
        if success:
            self.add_function_to_config(GadgetFunction.HID)
        
        return success
    
    def setup_hid_mouse(self) -> bool:
        """Quick setup for HID mouse."""
        if not self.ensure_gadget():
            return False
        
        success = self.add_hid_function(HIDConfig(
            protocol=2,  # Mouse
            subclass=1,
            report_length=4,
        ))
        
        if success:
            self.add_function_to_config(GadgetFunction.HID)
        
        return success
    
    def setup_mass_storage(self, file_path: str, read_only: bool = False) -> bool:
        """Quick setup for Mass Storage."""
        if not self.ensure_gadget():
            return False
        
        success = self.add_mass_storage_function(MassStorageConfig(
            file_path=file_path,
            read_only=read_only,
        ))
        
        if success:
            self.add_function_to_config(GadgetFunction.MASS_STORAGE)
        
        return success
    
    def setup_rndis(self, host_ip: str = "192.168.7.1", dev_ip: str = "192.168.7.2") -> bool:
        """Quick setup for RNDIS (USB Ethernet)."""
        if not self.ensure_gadget():
            return False
        
        success = self.add_network_function(GadgetFunction.RNDIS, NetworkConfig(
            host_ip=host_ip,
            dev_ip=dev_ip,
        ))
        
        if success:
            self.add_function_to_config(GadgetFunction.RNDIS)
        
        return success
    
    def setup_ecm(self, host_ip: str = "192.168.7.1", dev_ip: str = "192.168.7.2") -> bool:
        """Quick setup for ECM (Ethernet Control Model)."""
        if not self.ensure_gadget():
            return False
        
        success = self.add_network_function(GadgetFunction.ECM, NetworkConfig(
            host_ip=host_ip,
            dev_ip=dev_ip,
        ))
        
        if success:
            self.add_function_to_config(GadgetFunction.ECM)
        
        return success
    
    def setup_serial(self) -> bool:
        """Quick setup for Serial (ACM)."""
        if not self.ensure_gadget():
            return False
        
        success = self.add_serial_function()
        
        if success:
            self.add_function_to_config(GadgetFunction.ACM)
        
        return success


# Pre-built report descriptors
class HIDReportDescriptors:
    """Pre-defined HID report descriptors."""
    
    # Standard keyboard (8 bytes)
    KEYBOARD = bytes([
        0x05, 0x01,        # Usage Page (Generic Desktop Ctrls)
        0x09, 0x06,        # Usage (Keyboard)
        0xA1, 0x01,        # Collection (Application)
        0x05, 0x07,        #   Usage Page (Kbrd/Keypad)
        0x19, 0xE0,        #   Usage Minimum (0xE0)
        0x29, 0xE7,        #   Usage Maximum (0xE7)
        0x15, 0x00,        #   Logical Minimum (0)
        0x25, 0x01,        #   Logical Maximum (1)
        0x75, 0x01,        #   Report Size (1)
        0x95, 0x08,        #   Report Count (8)
        0x81, 0x02,        #   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Pos)
        0x95, 0x01,        #   Report Count (1)
        0x75, 0x08,        #   Report Size (8)
        0x81, 0x03,        #   Input (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Pos)
        0x95, 0x05,        #   Report Count (5)
        0x75, 0x01,        #   Report Size (1)
        0x05, 0x08,        #   Usage Page (LEDs)
        0x19, 0x01,        #   Usage Minimum (Num Lock)
        0x29, 0x05,        #   Usage Maximum (Kana)
        0x91, 0x02,        #   Output (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Pos,Non-volatile)
        0x95, 0x01,        #   Report Count (1)
        0x75, 0x03,        #   Report Size (3)
        0x91, 0x03,        #   Output (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Pos,Non-volatile)
        0x95, 0x06,        #   Report Count (6)
        0x75, 0x08,        #   Report Size (8)
        0x15, 0x00,        #   Logical Minimum (0)
        0x25, 0x65,        #   Logical Maximum (101)
        0x05, 0x07,        #   Usage Page (Kbrd/Keypad)
        0x19, 0x00,        #   Usage Minimum (0x00)
        0x29, 0x65,        #   Usage Maximum (101)
        0x81, 0x00,        #   Input (Data,Array,Abs,No Wrap,Linear,Preferred State,No Null Pos)
        0xC0,              # End Collection
    ])
    
    # Standard mouse (4 bytes)
    MOUSE = bytes([
        0x05, 0x01,        # Usage Page (Generic Desktop Ctrls)
        0x09, 0x02,        # Usage (Mouse)
        0xA1, 0x01,        # Collection (Application)
        0x09, 0x01,        #   Usage (Pointer)
        0xA1, 0x00,        #   Collection (Physical)
        0x05, 0x09,        #   Usage Page (Button)
        0x19, 0x01,        #   Usage Minimum (0x01)
        0x29, 0x03,        #   Usage Maximum (0x03)
        0x15, 0x00,        #   Logical Minimum (0)
        0x25, 0x01,        #   Logical Maximum (1)
        0x95, 0x03,        #   Report Count (3)
        0x75, 0x01,        #   Report Size (1)
        0x81, 0x02,        #   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Pos)
        0x95, 0x01,        #   Report Count (1)
        0x75, 0x05,        #   Report Size (5)
        0x81, 0x03,        #   Input (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Pos)
        0x05, 0x01,        #   Usage Page (Generic Desktop Ctrls)
        0x09, 0x30,        #   Usage (X)
        0x09, 0x31,        #   Usage (Y)
        0x15, 0x81,        #   Logical Minimum (-127)
        0x25, 0x7F,        #   Logical Maximum (127)
        0x75, 0x08,        #   Report Size (8)
        0x95, 0x02,        #   Report Count (2)
        0x81, 0x06,        #   Input (Data,Var,Rel,No Wrap,Linear,Preferred State,No Null Pos)
        0xC0,              # End Collection
        0xC0,              # End Collection
    ])


# Export all public classes
__all__ = [
    "GadgetFunction",
    "GadgetSpeed",
    "GadgetConfig",
    "HIDConfig",
    "MassStorageConfig",
    "NetworkConfig",
    "SerialConfig",
    "USBGadgetManager",
    "HIDReportDescriptors",
]