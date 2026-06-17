"""
HID Injector - uinput (local) + usb-gadget (configfs HID) payload injection.

Provides:
- uinput-based HID injection for local machine
- USB gadget HID injection via configfs
- Payload queue with live execution log
- DuckyScript integration for convenient payload creation
"""

import asyncio
import os
import structlog
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Union, AsyncGenerator

try:
    import uinput
    UINPUT_AVAILABLE = True
except ImportError:
    UINPUT_AVAILABLE = False

logger = structlog.get_logger(__name__)


class InjectionMode(Enum):
    """HID injection mode."""
    UINPUT = "uinput"           # Local uinput (requires /dev/uinput)
    USB_GADGET = "usb_gadget"   # USB Gadget HID (configfs)


class InjectionStatus(Enum):
    """Injection status."""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class InjectionConfig:
    """Configuration for HID injection."""
    mode: InjectionMode = InjectionMode.UINPUT
    uinput_device_name: str = "Urban Hack Sentinel HID"
    usb_gadget_name: str = "urban_hs"
    layout: str = "us"
    default_delay: int = 10  # ms between keystrokes
    inter_key_delay: int = 5  # ms between key press/release


@dataclass
class InjectionEvent:
    """Single injection event."""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_type: str = ""  # key_down, key_up, key_press, mouse_move, mouse_click, delay
    keycode: Optional[int] = None
    modifier: int = 0
    x: int = 0
    y: int = 0
    delay_ms: int = 0
    description: str = ""


@dataclass
class InjectionReport:
    """Report of an injection run."""
    start_time: datetime
    end_time: datetime
    total_keys: int = 0
    total_delays: int = 0
    events: List[InjectionEvent] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    status: InjectionStatus = InjectionStatus.COMPLETED


class UInputInjector:
    """HID injector using Linux uinput (local)."""
    
    def __init__(self, config: Optional[InjectionConfig] = None):
        self.config = config or InjectionConfig()
        self._device: Optional[Any] = None
        self._running = False
        self._events: List[InjectionEvent] = []
        
        if not UINPUT_AVAILABLE:
            logger.warning("uinput not available, install python-uinput")
    
    async def start(self) -> bool:
        """Initialize uinput device."""
        if not UINPUT_AVAILABLE:
            logger.error("uinput not available")
            return False
        
        try:
            # Define device capabilities
            events = (
                uinput.EV_KEY,
                uinput.EV_REL,
                uinput.EV_ABS,
                uinput.EV_SYN,
            )
            
            # Common keys
            keys = [
                uinput.KEY_A, uinput.KEY_B, uinput.KEY_C, uinput.KEY_D, uinput.KEY_E,
                uinput.KEY_F, uinput.KEY_G, uinput.KEY_H, uinput.KEY_I, uinput.KEY_J,
                uinput.KEY_K, uinput.KEY_L, uinput.KEY_M, uinput.KEY_N, uinput.KEY_O,
                uinput.KEY_P, uinput.KEY_Q, uinput.KEY_R, uinput.KEY_S, uinput.KEY_T,
                uinput.KEY_U, uinput.KEY_V, uinput.KEY_W, uinput.KEY_X, uinput.KEY_Y,
                uinput.KEY_Z,
                uinput.KEY_1, uinput.KEY_2, uinput.KEY_3, uinput.KEY_4, uinput.KEY_5,
                uinput.KEY_6, uinput.KEY_7, uinput.KEY_8, uinput.KEY_9, uinput.KEY_0,
                uinput.KEY_ENTER, uinput.KEY_ESC, uinput.KEY_BACKSPACE, uinput.KEY_TAB,
                uinput.KEY_SPACE, uinput.KEY_LEFTSHIFT, uinput.KEY_RIGHTSHIFT,
                uinput.KEY_LEFTCTRL, uinput.KEY_RIGHTCTRL, uinput.KEY_LEFTALT, uinput.KEY_RIGHTALT,
                uinput.KEY_LEFTMETA, uinput.KEY_RIGHTMETA,  # GUI/Windows key
                uinput.KEY_UP, uinput.KEY_DOWN, uinput.KEY_LEFT, uinput.KEY_RIGHT,
                uinput.KEY_TAB, uinput.KEY_ENTER, uinput.KEY_ESC, uinput.KEY_BACKSPACE,
                uinput.KEY_F1, uinput.KEY_F2, uinput.KEY_F3, uinput.KEY_F4,
                uinput.KEY_F5, uinput.KEY_F6, uinput.KEY_F7, uinput.KEY_F8,
                uinput.KEY_F9, uinput.KEY_F10, uinput.KEY_F11, uinput.KEY_F12,
                uinput.KEY_DELETE, uinput.KEY_HOME, uinput.KEY_END, uinput.KEY_PAGEUP, uinput.KEY_PAGEDOWN,
                uinput.KEY_INSERT, uinput.KEY_DELETE,
                uinput.BTN_LEFT, uinput.BTN_RIGHT, uinput.BTN_MIDDLE,
            ]
            
            rel_axes = [uinput.REL_X, uinput.REL_Y, uinput.REL_WHEEL]
            
            self._device = uinput.Device(
                events=events,
                name=self.config.uinput_device_name,
                vendor=0x1234,
                product=0x5678,
                version=1,
            )
            
            self._running = True
            logger.info("uinput injector started", device=self.config.uinput_device_name)
            return True
            
        except Exception as e:
            logger.error("Failed to start uinput injector", error=str(e))
            return False
    
    async def stop(self):
        """Stop uinput injector."""
        if self._device:
            try:
                self._device.destroy()
            except Exception as e:
                logger.warning("Error closing uinput device", error=str(e))
            self._device = None
        self._running = False
        logger.info("uinput injector stopped")
    
    def is_running(self) -> bool:
        return self._running
    
    def _log_event(self, event: InjectionEvent):
        """Log injection event."""
        self._events.append(event)
        logger.debug("Injection event", **event.__dict__)
    
    def key_down(self, keycode: int, modifier: int = 0) -> bool:
        """Press a key."""
        if not self._running or not self._device:
            return False
        
        try:
            self._device.emit_click(keycode)
            self._log_event(InjectionEvent(
                event_type="key_down",
                keycode=keycode,
                modifier=modifier,
            ))
            return True
        except Exception as e:
            logger.error("Key down failed", keycode=keycode, error=str(e))
            return False
    
    def key_up(self, keycode: int, modifier: int = 0) -> bool:
        """Release a key."""
        if not self._running or not self._device:
            return False
        
        try:
            # uinput emits key up automatically on emit_click
            # For explicit key up, we can emit with value 0
            self._device.emit(keycode, 0)
            self._log_event(InjectionEvent(
                event_type="key_up",
                keycode=keycode,
                modifier=modifier,
            ))
            return True
        except Exception as e:
            logger.error("Key up failed", keycode=keycode, error=str(e))
            return False
    
    async def key_press(self, keycode: int, modifier: int = 0, delay_ms: Optional[int] = None) -> bool:
        """Press and release a key."""
        if not self._running or not self._device:
            return False
        
        try:
            self._device.emit_click(keycode)
            self._log_event(InjectionEvent(
                event_type="key_press",
                keycode=keycode,
                modifier=modifier,
            ))
            
            delay = delay_ms or self.config.default_delay
            if delay > 0:
                await asyncio.sleep(delay / 1000.0)
            
            return True
        except Exception as e:
            logger.error("Key press failed", keycode=keycode, error=str(e))
            return False
    
    async def type_string(self, text: str, delay_ms: Optional[int] = None) -> bool:
        """Type a string character by character."""
        if not self._running or not self._device:
            return False
        
        for char in text:
            # Convert char to keycode (simplified)
            keycode = self._char_to_keycode(char)
            if keycode:
                if not await self.key_press(keycode, delay_ms=delay_ms):
                    return False
            else:
                logger.warning("Character not mappable", char=char)
            
            inter_delay = delay_ms or self.config.inter_key_delay
            if inter_delay > 0:
                await asyncio.sleep(inter_delay / 1000.0)
        
        return True
    
    def _char_to_keycode(self, char: str) -> Optional[int]:
        """Convert character to uinput keycode (simplified)."""
        # This is a simplified mapping - in production would use layout mapping
        key_map = {
            'a': 30, 'b': 48, 'c': 46, 'd': 32, 'e': 18, 'f': 33, 'g': 34, 'h': 35,
            'i': 23, 'j': 36, 'k': 37, 'l': 38, 'm': 50, 'n': 49, 'o': 24, 'p': 25,
            'q': 16, 'r': 19, 's': 31, 't': 20, 'u': 22, 'v': 47, 'w': 17, 'x': 45, 'y': 21, 'z': 44,
            '1': 2, '2': 3, '2': 3, '3': 4, '4': 5, '5': 6, '6': 7, '7': 8, '8': 9, '9': 10, '0': 11,
            ' ': 57, '\n': 28, '\t': 15, '\r': 28,
        }
        return key_map.get(char.lower())
    
    def mouse_move(self, x: int, y: int) -> bool:
        """Move mouse relatively."""
        if not self._running or not self._device:
            return False
        
        try:
            self._device.emit(uinput.REL_X, x)
            self._device.emit(uinput.REL_Y, y)
            self._device.emit(uinput.EV_SYN, uinput.SYN_REPORT, 0)
            
            self._log_event(InjectionEvent(
                event_type="mouse_move",
                x=x, y=y,
            ))
            return True
        except Exception as e:
            logger.error("Mouse move failed", error=str(e))
            return False
    
    def mouse_click(self, button: int = 1) -> bool:
        """Click mouse button (1=left, 2=right, 3=middle)."""
        if not self._running or not self._device:
            return False
        
        try:
            btn = {1: uinput.BTN_LEFT, 2: uinput.BTN_RIGHT, 3: uinput.BTN_MIDDLE}.get(button, uinput.BTN_LEFT)
            self._device.emit_click(btn)
            self._log_event(InjectionEvent(
                event_type="mouse_click",
                description=f"button_{button}",
            ))
            return True
        except Exception as e:
            logger.error("Mouse click failed", error=str(e))
            return False
    
    async def delay(self, ms: int):
        """Add delay."""
        self._log_event(InjectionEvent(
            event_type="delay",
            delay_ms=ms,
        ))
        await asyncio.sleep(ms / 1000.0)
    
    def get_events(self) -> List[InjectionEvent]:
        """Get recorded events."""
        return self._events.copy()
    
    def clear_events(self):
        """Clear recorded events."""
        self._events.clear()


class USBGadgetInjector:
    """HID injector using USB Gadget (configfs HID)."""
    
    def __init__(self, config: Optional[InjectionConfig] = None):
        self.config = config or InjectionConfig(mode=InjectionMode.USB_GADGET)
        self._gadget: Optional[Any] = None
        self._running = False
        self._events: List[InjectionEvent] = []
        self._report: Optional[Any] = None  # HID report endpoint
    
    async def start(self) -> bool:
        """Initialize USB gadget HID."""
        try:
            from urban_hs.modules.hid import USBGadgetManager, HIDReportDescriptors, HIDConfig
            
            self._gadget = USBGadgetManager()
            
            # Create gadget with HID keyboard
            if not self._gadget.setup_hid_keyboard(HIDReportDescriptors.KEYBOARD):
                logger.error("Failed to setup HID keyboard")
                return False
            
            # Bind to UDC
            if not self._gadget.bind_udc():
                logger.error("Failed to bind UDC")
                return False
            
            # Find HID device endpoint
            self._report = await self._find_hid_report()
            if not self._report:
                logger.error("HID report endpoint not found")
                return False
            
            self._running = True
            logger.info("USB Gadget HID injector started")
            return True
            
        except Exception as e:
            logger.error("Failed to start USB Gadget injector", error=str(e))
            return False
    
    async def _find_hid_report(self) -> Optional[str]:
        """Find the HID report endpoint in /dev/hidg*."""
        import glob
        for path in glob.glob("/dev/hidg*"):
            return path
        # Also check /dev/hidraw*
        for path in glob.glob("/dev/hidraw*"):
            return path
        return None
    
    async def stop(self):
        """Stop USB gadget injector."""
        if self._gadget:
            self._gadget.destroy_gadget()
            self._gadget = None
        self._running = False
        logger.info("USB Gadget HID injector stopped")
    
    def is_running(self) -> bool:
        return self._running
    
    def _log_event(self, event: InjectionEvent):
        self._events.append(event)


class HIDInjector:
    """
    Main HID Injector - supports both uinput and USB Gadget modes.
    
    Usage:
        injector = HIDInjector()
        await injector.start(InjectionMode.UINPUT)
        await injector.type_string("Hello World")
        await injector.stop()
    """
    
    def __init__(self, config: Optional[InjectionConfig] = None):
        self.config = config or InjectionConfig()
        self._uinput: Optional[UInputInjector] = None
        self._usb_gadget: Optional[USBGadgetInjector] = None
        self._active_injector: Optional[UInputInjector] = None
        self._running = False
        self._events: List[InjectionEvent] = []
    
    async def start(self, mode: InjectionMode = InjectionMode.UINPUT) -> bool:
        """Start HID injector in specified mode."""
        self.config.mode = mode
        
        if mode == InjectionMode.UINPUT:
            self._uinput = UInputInjector(self.config)
            success = await self._uinput.start()
            if success:
                self._active_injector = self._uinput
        
        elif mode == InjectionMode.USB_GADGET:
            self._usb_gadget = USBGadgetInjector(self.config)
            success = await self._usb_gadget.start()
            if success:
                self._active_injector = self._usb_gadget
        
        else:
            logger.error("Unknown injection mode", mode=mode)
            return False
        
        if success:
            self._running = True
            logger.info("HID injector started", mode=mode.value)
        
        return success
    
    async def stop(self):
        """Stop HID injector."""
        if self._uinput:
            await self._uinput.stop()
            self._uinput = None
        
        if self._usb_gadget:
            await self._usb_gadget.stop()
            self._usb_gadget = None
        
        self._active_injector = None
        self._running = False
        logger.info("HID injector stopped")
    
    def is_running(self) -> bool:
        return self._running
    
    async def type_string(self, text: str, delay_ms: Optional[int] = None) -> bool:
        """Type a string."""
        if not self._active_injector:
            return False
        
        if hasattr(self._active_injector, 'type_string'):
            return await self._active_injector.type_string(text, delay_ms)
        else:
            # Fallback: type character by character
            for char in text:
                if not await self.key_press(char):
                    return False
            return True
    
    async def key_press(self, key: Union[str, int], modifier: int = 0, delay_ms: Optional[int] = None) -> bool:
        """Press a key."""
        if not self._active_injector:
            return False
        
        if hasattr(self._active_injector, 'key_press'):
            if isinstance(key, str):
                return await self._active_injector.type_string(key)
            return await self._active_injector.key_press(key, modifier, delay_ms)
        return False
    
    async def key_down(self, keycode: int, modifier: int = 0) -> bool:
        """Press key down."""
        if not self._active_injector or not hasattr(self._active_injector, 'key_down'):
            return False
        return self._active_injector.key_down(keycode, modifier)
    
    async def key_up(self, keycode: int, modifier: int = 0) -> bool:
        """Release key."""
        if not self._active_injector or not hasattr(self._active_injector, 'key_up'):
            return False
        return self._active_injector.key_up(keycode, modifier)
    
    def mouse_move(self, x: int, y: int) -> bool:
        """Move mouse relatively."""
        if not self._active_injector or not hasattr(self._active_injector, 'mouse_move'):
            return False
        return self._active_injector.mouse_move(x, y)
    
    def mouse_click(self, button: int = 1) -> bool:
        """Click mouse button."""
        if not self._active_injector or not hasattr(self._active_injector, 'mouse_click'):
            return False
        return self._active_injector.mouse_click(button)
    
    async def delay(self, ms: int):
        """Add delay."""
        if self._active_injector and hasattr(self._active_injector, 'delay'):
            await self._active_injector.delay(ms)
        else:
            await asyncio.sleep(ms / 1000.0)
    
    async def execute_ducky(self, script_path: str, layout: str = "us") -> bool:
        """Execute DuckyScript file."""
        try:
            from urban_hs.modules.hid import DuckyCompiler, load_ducky_file
            compiler = DuckyCompiler(KeyboardLayout(layout))
            script = compiler.compile_file(script_path)
            
            if script.errors:
                for error in script.errors:
                    logger.error("DuckyScript error", error=error)
                return False
            
            reports = compiler.encode_to_hid(script)
            
            # Send reports via active injector
            for report in reports:
                # Skip DELAY markers (high bit 0x80 set in first byte)
                if report[0] & 0x80:
                    delay_ms = ((report[0] & 0x7F) << 8) | report[1]
                    await asyncio.sleep(delay_ms / 1000.0)
                    continue
                
                # Inject report bytes
                if hasattr(self._active_injector, '_report') and self._active_injector._report:
                    with open(self._active_injector._report, 'wb') as f:
                        f.write(report)
                else:
                    logger.warning("No HID report endpoint for ducky execution")
            
            return True
        except Exception as e:
            logger.error("DuckyScript execution failed", error=str(e))
            return False
    
    def get_events(self) -> List[InjectionEvent]:
        """Get all recorded injection events."""
        events = []
        if self._uinput:
            events.extend(self._uinput._events)
        if self._usb_gadget:
            events.extend(self._usb_gadget._events)
        return events
    
    def is_running(self) -> bool:
        return self._running


# Convenience functions
async def quick_type(text: str, mode: InjectionMode = InjectionMode.UINPUT, layout: str = "us") -> bool:
    """Quick helper to type a string."""
    injector = HIDInjector(InjectionConfig(mode=mode, layout=layout))
    if await injector.start(mode):
        result = await injector.type_string(text)
        await injector.stop()
        return result
    return False


async def quick_ducky(script_path: str, mode: InjectionMode = InjectionMode.UINPUT, layout: str = "us") -> bool:
    """Quick helper to execute DuckyScript."""
    injector = HIDInjector(InjectionConfig(mode=mode, layout=layout))
    if await injector.start(mode):
        result = injector.execute_ducky(script_path, layout)
        await injector.stop()
        return result
    return False


# Export all public classes
__all__ = [
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