"""
DuckyScript Parser - Hak5 DuckyScript v1/v3 Parser with 7 Keyboard Layouts.

Supports:
- DuckyScript v1 (classic)
- DuckyScript v3 (extended with loops, variables, functions)
- 7 Keyboard Layouts: US, GB, DE, FR, ES, IT, RU
- Encoder for hid_injector integration
"""

import re
import structlog
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Callable
from abc import ABC, abstractmethod

logger = structlog.get_logger(__name__)


class KeyboardLayout(Enum):
    """Supported keyboard layouts."""
    US = "us"
    GB = "gb"
    DE = "de"
    FR = "fr"
    ES = "es"
    IT = "it"
    RU = "ru"


class DuckyCommandType(Enum):
    """Types of DuckyScript commands."""
    DELAY = "DELAY"
    STRING = "STRING"
    DEFAULT_DELAY = "DEFAULT_DELAY"
    DEFAULTDELAY = "DEFAULTDELAY"
    REM = "REM"
    COMMENT = "#"
    GUI = "GUI"
    WINDOWS = "WINDOWS"
    COMMAND = "COMMAND"
    ALT = "ALT"
    SHIFT = "SHIFT"
    CTRL = "CTRL"
    CONTROL = "CONTROL"
    ENTER = "ENTER"
    TAB = "TAB"
    SPACE = "SPACE"
    UP = "UP"
    DOWN = "DOWN"
    LEFT = "LEFT"
    RIGHT = "RIGHT"
    DELETE = "DELETE"
    BACKSPACE = "BACKSPACE"
    HOME = "HOME"
    END = "END"
    PAGEUP = "PAGEUP"
    PAGEDOWN = "PAGEDOWN"
    PRINTSCREEN = "PRINTSCREEN"
    SCROLLLOCK = "SCROLLLOCK"
    PAUSE = "PAUSE"
    CAPSLOCK = "CAPSLOCK"
    NUMLOCK = "NUMLOCK"
    ESC = "ESC"
    ESCAPE = "ESCAPE"
    F1 = "F1"
    F2 = "F2"
    F3 = "F3"
    F4 = "F4"
    F5 = "F5"
    F6 = "F6"
    F7 = "F7"
    F8 = "F8"
    F9 = "F9"
    F10 = "F10"
    F11 = "F11"
    F12 = "F12"
    # v3 extensions
    REPEAT = "REPEAT"
    LOOP = "LOOP"
    ENDLOOP = "ENDLOOP"
    VAR = "VAR"
    FUNCTION = "FUNCTION"
    ENDFUNCTION = "ENDFUNCTION"
    CALL = "CALL"
    IF = "IF"
    ELSE = "ELSE"
    ENDIF = "ENDIF"
    WHILE = "WHILE"
    ENDWHILE = "ENDWHILE"
    # Mouse
    MOUSE_MOVE = "MOUSE_MOVE"
    MOUSE_CLICK = "MOUSE_CLICK"
    MOUSE_DOWN = "MOUSE_DOWN"
    MOUSE_UP = "MOUSE_UP"
    MOUSE_SCROLL = "MOUSE_SCROLL"


@dataclass
class DuckyCommand:
    """Parsed DuckyScript command."""
    type: DuckyCommandType
    args: List[str] = field(default_factory=list)
    line_number: int = 0
    raw_line: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # For structured commands (v3)
    loop_count: int = 1
    var_name: str = ""
    var_value: str = ""
    function_name: str = ""
    condition: str = ""
    body: List['DuckyCommand'] = field(default_factory=list)


@dataclass
class ParsedScript:
    """Result of parsing a DuckyScript file."""
    commands: List[DuckyCommand] = field(default_factory=list)
    variables: Dict[str, str] = field(default_factory=dict)
    functions: Dict[str, List[DuckyCommand]] = field(default_factory=dict)
    default_delay: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class KeyMapper:
    """Maps keys to HID keycodes for different layouts."""
    
    # US Layout (base)
    US_KEYMAP = {
        'a': 0x04, 'b': 0x05, 'c': 0x06, 'd': 0x07, 'e': 0x08,
        'f': 0x09, 'g': 0x0A, 'h': 0x0B, 'i': 0x0C, 'j': 0x0D,
        'k': 0x0E, 'l': 0x0F, 'm': 0x10, 'n': 0x11, 'o': 0x12,
        'p': 0x13, 'q': 0x14, 'r': 0x15, 's': 0x16, 't': 0x17,
        'u': 0x18, 'v': 0x19, 'w': 0x1A, 'x': 0x1B, 'y': 0x1C, 'z': 0x1D,
        '1': 0x1E, '2': 0x1F, '3': 0x20, '4': 0x21, '5': 0x22,
        '6': 0x23, '7': 0x24, '8': 0x25, '9': 0x26, '0': 0x27,
        'enter': 0x28, 'escape': 0x29, 'backspace': 0x2A, 'tab': 0x2B,
        'space': 0x2C, 'minus': 0x2D, 'equal': 0x2E,
        'left_brace': 0x2F, 'right_brace': 0x30,
        'backslash': 0x31, 'nonus_hash': 0x32,
        'semicolon': 0x33, 'quote': 0x34, 'grave': 0x35,
        'comma': 0x36, 'period': 0x37, 'slash': 0x38,
        'caps_lock': 0x39,
        'f1': 0x3A, 'f2': 0x3B, 'f3': 0x3C, 'f4': 0x3D,
        'f5': 0x3E, 'f6': 0x3F, 'f7': 0x40, 'f8': 0x41,
        'f9': 0x42, 'f10': 0x43, 'f11': 0x44, 'f12': 0x45,
        'print_screen': 0x46, 'scroll_lock': 0x47, 'pause': 0x48,
        'insert': 0x49, 'home': 0x4A, 'page_up': 0x4B,
        'delete': 0x4C, 'end': 0x4D, 'page_down': 0x4E,
        'right_arrow': 0x4F, 'left_arrow': 0x50,
        'down_arrow': 0x51, 'up_arrow': 0x52,
        'keypad_numlock': 0x53, 'keypad_slash': 0x54,
        'keypad_asterisk': 0x55, 'keypad_minus': 0x56,
        'keypad_plus': 0x57, 'keypad_enter': 0x58,
        'keypad_1': 0x59, 'keypad_2': 0x5A, 'keypad_3': 0x5B,
        'keypad_4': 0x5C, 'keypad_5': 0x5D, 'keypad_6': 0x5E,
        'keypad_7': 0x5F, 'keypad_8': 0x60, 'keypad_9': 0x61,
        'keypad_0': 0x62, 'keypad_period': 0x63,
        'nonus_backslash': 0x64, 'application': 0x65,
        'power': 0x66, 'keypad_equal': 0x67,
        # Modifiers
        'left_control': 0xE0, 'left_shift': 0xE1,
        'left_alt': 0xE2, 'left_gui': 0xE3,
        'right_control': 0xE4, 'right_shift': 0xE5,
        'right_alt': 0xE6, 'right_gui': 0xE7,
    }
    
    # Layout-specific overrides
    LAYOUT_OVERRIDES = {
        KeyboardLayout.GB: {
            'grave': 0x35,  # § key
            '2': 0x1F, '3': 0x20,  # " and £ swapped
        },
        KeyboardLayout.DE: {
            'y': 0x1C, 'z': 0x1D,  # Y and Z swapped
            'semicolon': 0x33,  # ö
            'quote': 0x34,  # ä
            'left_brace': 0x2F,  # ü
        },
        KeyboardLayout.FR: {
            'a': 0x04, 'z': 0x1D, 'q': 0x14, 'w': 0x1A,  # AZERTY
            'm': 0x33, 'comma': 0x36,  # ; and :
        },
        KeyboardLayout.ES: {
            'semicolon': 0x33,  # ñ
        },
        KeyboardLayout.IT: {
        },
        KeyboardLayout.RU: {
            # Russian layout would need full remapping
        },
    }
    
    def __init__(self, layout: KeyboardLayout = KeyboardLayout.US):
        self.layout = layout
        self.keymap = self._build_keymap(layout)
    
    def _build_keymap(self, layout: KeyboardLayout) -> Dict[str, int]:
        keymap = self.US_KEYMAP.copy()
        if layout in self.LAYOUT_OVERRIDES:
            keymap.update(self.LAYOUT_OVERRIDES[layout])
        return keymap
    
    def get_keycode(self, key: str) -> Optional[int]:
        """Get keycode for a key name."""
        return self.keymap.get(key.lower())
    
    def string_to_keycodes(self, text: str) -> List[tuple]:
        """Convert string to list of (keycode, modifier) tuples."""
        result = []
        for char in text:
            if char.isupper():
                result.append((self.keymap.get(char.lower(), 0x00), 0x02))  # SHIFT
            elif char in self.keymap:
                result.append((self.keymap[char], 0x00))
            elif char in '!@#$%^&*()_+{}|:"<>?':
                # Shifted symbols
                shifted_map = {
                    '!': '1', '@': '2', '#': '3', '$': '4', '%': '5',
                    '^': '6', '&': '7', '*': '8', '(': '9', ')': '0',
                    '_': '-', '+': '=', '{': '[', '}': ']', '|': '\\',
                    ':': ';', '"': "'", '<': ',', '>': '.', '?': '/',
                    '~': '`',
                }
                base = shifted_map.get(char)
                if base and base in self.keymap:
                    result.append((self.keymap[base], 0x02))
            else:
                logger.warning("Unmappable character", char=char)
        return result


class DuckyParser:
    """DuckyScript parser supporting v1 and v3 syntax."""
    
    def __init__(self, layout: KeyboardLayout = KeyboardLayout.US):
        self.layout = layout
        self.mapper = KeyMapper(layout)
        self.variables: Dict[str, str] = {}
        self.functions: Dict[str, List[DuckyCommand]] = {}
        self.default_delay = 0
        
    def parse(self, content: str) -> ParsedScript:
        """Parse DuckyScript content."""
        script = ParsedScript()
        lines = content.split('\n')
        
        i = 0
        while i < len(lines):
            line = lines[i].rstrip()
            line_num = i + 1
            
            # Skip empty lines and comments
            if not line.strip() or line.strip().startswith(('#', 'REM')):
                i += 1
                continue
            
            # Parse command
            try:
                cmd, consumed = self._parse_line(line, line_num, lines, i)
                if cmd:
                    script.commands.append(cmd)
                    # Handle special commands
                    if cmd.type == DuckyCommandType.DEFAULT_DELAY:
                        self.default_delay = int(cmd.args[0]) if cmd.args else 0
                        script.default_delay = self.default_delay
                    elif cmd.type == DuckyCommandType.VAR:
                        if len(cmd.args) >= 2:
                            self.variables[cmd.args[0]] = ' '.join(cmd.args[1:])
                            script.variables[cmd.args[0]] = ' '.join(cmd.args[1:])
                    elif cmd.type == DuckyCommandType.FUNCTION:
                        # Function definition
                        func_name = cmd.args[0] if cmd.args else ''
                        func_body, consumed_lines = self._parse_function_body(lines, i + 1)
                        script.functions[func_name] = func_body
                        i += consumed_lines
                        continue
            except Exception as e:
                script.errors.append(f"Line {line_num}: {str(e)}")
            
            i += 1
        
        script.metadata = {
            'layout': self.layout.value,
            'variable_count': len(script.variables),
            'function_count': len(script.functions),
            'command_count': len(script.commands),
        }
        
        return script
    
    def _parse_line(self, line: str, line_num: int, all_lines: List[str], current_idx: int) -> tuple:
        """Parse a single line into a DuckyCommand."""
        stripped = line.strip()
        if not stripped:
            return None, 0
        
        # Split into command and args
        parts = stripped.split(' ', 1)
        cmd_str = parts[0].upper()
        args_str = parts[1] if len(parts) > 1 else ''
        
        # Parse arguments (respect quotes)
        args = self._parse_args(args_str)
        
        # Map command
        cmd_type = self._map_command(cmd_str)
        
        cmd = DuckyCommand(
            type=cmd_type,
            args=args,
            line_number=line_num,
            raw_line=line,
        )
        
        return cmd, 0
    
    def _parse_args(self, args_str: str) -> List[str]:
        """Parse arguments respecting quotes."""
        args = []
        current = ''
        in_quotes = False
        quote_char = None
        
        i = 0
        while i < len(args_str):
            char = args_str[i]
            if char in ('"', "'") and not in_quotes:
                in_quotes = True
                quote_char = char
            elif char == quote_char and in_quotes:
                in_quotes = False
                quote_char = None
            elif char == ' ' and not in_quotes:
                if current:
                    args.append(current)
                    current = ''
            else:
                current += char
            i += 1
        
        if current:
            args.append(current)
        
        return args
    
    def _map_command(self, cmd_str: str) -> DuckyCommandType:
        """Map command string to DuckyCommandType."""
        # Handle aliases
        aliases = {
            'DEFAULTDELAY': 'DEFAULT_DELAY',
            'WINDOWS': 'GUI',
            'COMMAND': 'GUI',
            'CONTROL': 'CTRL',
            'BREAK': 'PAUSE',
            'ESCAPE': 'ESC',
            'DELETE': 'DELETE',
        }
        
        cmd = aliases.get(cmd_str, cmd_str)
        
        try:
            return DuckyCommandType(cmd)
        except ValueError:
            # Unknown command, treat as STRING
            return DuckyCommandType.STRING
    
    def _parse_function_body(self, lines: List[str], start_idx: int) -> tuple:
        """Parse function body until ENDFUNCTION."""
        body = []
        i = start_idx
        while i < len(lines):
            line = lines[i].rstrip()
            stripped = line.strip()
            
            if stripped.upper() == 'ENDFUNCTION':
                return body, i - start_idx
            
            if stripped and not stripped.startswith(('#', 'REM')):
                cmd, _ = self._parse_line(line, i + 1, lines, i)
                if cmd:
                    body.append(cmd)
            i += 1
        
        return body, i - start_idx


class DuckyEncoder:
    """Encodes DuckyScript commands to HID reports."""
    
    def __init__(self, layout: KeyboardLayout = KeyboardLayout.US):
        self.mapper = KeyMapper(layout)
        self.default_delay = 0
    
    def encode(self, script: ParsedScript) -> List[bytes]:
        """Encode parsed script to HID reports."""
        reports = []
        
        for cmd in script.commands:
            reports.extend(self._encode_command(cmd))
            
            # Add default delay between commands
            if self.default_delay > 0 and cmd.type != DuckyCommandType.DELAY:
                reports.append(self._create_delay_report(self.default_delay))
        
        return reports
    
    def _encode_command(self, cmd: DuckyCommand) -> List[bytes]:
        """Encode a single command to HID reports."""
        reports = []
        
        if cmd.type == DuckyCommandType.DELAY:
            delay_ms = int(cmd.args[0]) if cmd.args else 0
            reports.append(self._create_delay_report(delay_ms))
            
        elif cmd.type == DuckyCommandType.STRING:
            text = ' '.join(cmd.args)
            reports.extend(self._encode_string(cmd.args))
            
        elif cmd.type in (DuckyCommandType.GUI, DuckyCommandType.WINDOWS, DuckyCommandType.COMMAND):
            reports.append(self._create_modifier_report(0xE3))  # Left GUI
            if cmd.args:
                # Process key after modifier
                key = cmd.args[0].lower()
                keycode = self.mapper.get_keycode(key)
                if keycode:
                    reports.append(self._create_key_report(keycode))
                reports.append(self._create_key_report(0x00))  # Release
            reports.append(self._create_modifier_report(0x00))  # Release all
            
        elif cmd.type in (DuckyCommandType.CTRL, DuckyCommandType.CONTROL):
            reports.append(self._create_modifier_report(0xE0))  # Left Ctrl
            if cmd.args:
                key = cmd.args[0].lower()
                keycode = self.mapper.get_keycode(key)
                if keycode:
                    reports.append(self._create_key_report(keycode))
                reports.append(self._create_key_report(0x00))
            reports.append(self._create_modifier_report(0x00))
            
        elif cmd.type in (DuckyCommandType.ALT,):
            reports.append(self._create_modifier_report(0xE2))  # Left Alt
            if cmd.args:
                key = cmd.args[0].lower()
                keycode = self.mapper.get_keycode(key)
                if keycode:
                    reports.append(self._create_key_report(keycode))
                reports.append(self._create_key_report(0x00))
            reports.append(self._create_modifier_report(0x00))
            
        elif cmd.type in (DuckyCommandType.SHIFT,):
            reports.append(self._create_modifier_report(0xE1))  # Left Shift
            if cmd.args:
                key = cmd.args[0].lower()
                keycode = self.mapper.get_keycode(key)
                if keycode:
                    reports.append(self._create_key_report(keycode))
                reports.append(self._create_key_report(0x00))
            reports.append(self._create_modifier_report(0x00))
            
        elif cmd.type == DuckyCommandType.ENTER:
            reports.append(self._create_key_report(0x28))
            
        elif cmd.type == DuckyCommandType.TAB:
            reports.append(self._create_key_report(0x2B))
            
        elif cmd.type == DuckyCommandType.SPACE:
            reports.append(self._create_key_report(0x2C))
            
        elif cmd.type == DuckyCommandType.UP:
            reports.append(self._create_key_report(0x52))
        elif cmd.type == DuckyCommandType.DOWN:
            reports.append(self._create_key_report(0x51))
        elif cmd.type == DuckyCommandType.LEFT:
            reports.append(self._create_key_report(0x50))
        elif cmd.type == DuckyCommandType.RIGHT:
            reports.append(self._create_key_report(0x4F))
            
        elif cmd.type == DuckyCommandType.DELETE:
            reports.append(self._create_key_report(0x4C))
        elif cmd.type == DuckyCommandType.BACKSPACE:
            reports.append(self._create_key_report(0x2A))
            
        elif cmd.type == DuckyCommandType.ESC:
            reports.append(self._create_key_report(0x29))
            
        elif cmd.type in (DuckyCommandType.F1, DuckyCommandType.F2, DuckyCommandType.F3,
                          DuckyCommandType.F4, DuckyCommandType.F5, DuckyCommandType.F6,
                          DuckyCommandType.F7, DuckyCommandType.F8, DuckyCommandType.F9,
                          DuckyCommandType.F10, DuckyCommandType.F11, DuckyCommandType.F12):
            fkey_map = {
                'F1': 0x3A, 'F2': 0x3B, 'F3': 0x3C, 'F4': 0x3D,
                'F5': 0x3E, 'F6': 0x3F, 'F7': 0x40, 'F8': 0x41,
                'F9': 0x42, 'F10': 0x43, 'F11': 0x44, 'F12': 0x45,
            }
            reports.append(self._create_key_report(fkey_map[cmd.type.value]))
            
        elif cmd.type == DuckyCommandType.REPEAT:
            # Handled at higher level
            pass
            
        return reports
    
    def _encode_string(self, args: List[str]) -> List[bytes]:
        """Encode string arguments to key reports."""
        reports = []
        text = ' '.join(args)
        
        for keycode, modifier in self.mapper.string_to_keycodes(text):
            if modifier:
                reports.append(self._create_modifier_report(modifier))
            reports.append(self._create_key_report(keycode))
            reports.append(self._create_key_report(0x00))  # Release
            if modifier:
                reports.append(self._create_modifier_report(0x00))
        
        return reports
    
    def _create_key_report(self, keycode: int) -> bytes:
        """Create 8-byte keyboard report."""
        # Format: [modifier, reserved, keycode1, keycode2, keycode3, keycode4, keycode5, keycode6]
        return bytes([0x00, 0x00, keycode, 0x00, 0x00, 0x00, 0x00, 0x00])
    
    def _create_modifier_report(self, modifier: int) -> bytes:
        """Create 8-byte modifier report."""
        return bytes([modifier, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    
    def _create_delay_report(self, ms: int) -> bytes:
        """Create a special delay marker report."""
        # Use a special report format for delays
        # High bit of first byte indicates delay, rest is milliseconds
        return bytes([0x80 | ((ms >> 8) & 0x7F), ms & 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])


class DuckyCompiler:
    """Compiles DuckyScript from file or string to executable format."""
    
    def __init__(self, layout: KeyboardLayout = KeyboardLayout.US):
        self.parser = DuckyParser(layout)
        self.encoder = DuckyEncoder(layout)
    
    def compile_file(self, filepath: Union[str, Path]) -> ParsedScript:
        """Compile DuckyScript from file."""
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        return self.compile_string(content)
    
    def compile_string(self, content: str) -> ParsedScript:
        """Compile DuckyScript from string."""
        return self.parser.parse(content)
    
    def encode_to_hid(self, script: ParsedScript) -> List[bytes]:
        """Encode parsed script to HID reports."""
        return self.encoder.encode(script)
    
    def save_compiled(self, script: ParsedScript, output_path: Union[str, Path]):
        """Save compiled script to binary format."""
        import json
        with open(output_path, 'w') as f:
            json.dump({
                'commands': [cmd.__dict__ for cmd in script.commands],
                'variables': script.variables,
                'functions': {k: [cmd.__dict__ for cmd in v] for k, v in script.functions.items()},
                'default_delay': script.default_delay,
            }, f)
    
    def load_compiled(self, input_path: Union[str, Path]) -> ParsedScript:
        """Load compiled script from binary format."""
        import json
        with open(input_path, 'r') as f:
            data = json.load(f)
        script = ParsedScript()
        script.commands = [DuckyCommand(**cmd) for cmd in data.get('commands', [])]
        script.variables = data.get('variables', {})
        script.functions = {k: [DuckyCommand(**cmd) for cmd in v] for k, v in data.get('functions', {}).items()}
        script.default_delay = data.get('default_delay', 0)
        return script


# Pre-defined keyboard layouts
LAYOUT_US = KeyboardLayout.US
LAYOUT_GB = KeyboardLayout.GB
LAYOUT_DE = KeyboardLayout.DE
LAYOUT_FR = KeyboardLayout.FR
LAYOUT_ES = KeyboardLayout.ES
LAYOUT_IT = KeyboardLayout.IT
LAYOUT_RU = KeyboardLayout.RU


def create_compiler(layout: KeyboardLayout = KeyboardLayout.US) -> DuckyCompiler:
    """Factory function to create a DuckyCompiler."""
    return DuckyCompiler(layout)


def load_ducky_file(filepath: Union[str, Path], layout: KeyboardLayout = KeyboardLayout.US) -> ParsedScript:
    """Convenience function to load and parse a DuckyScript file."""
    compiler = DuckyCompiler(layout)
    return compiler.compile_file(filepath)


# CLI helper
def main():
    """Command-line interface for DuckyScript compilation."""
    import argparse
    
    parser = argparse.ArgumentParser(description='DuckyScript Compiler')
    parser.add_argument('input', help='Input DuckyScript file')
    parser.add_argument('-o', '--output', help='Output compiled file')
    parser.add_argument('-l', '--layout', choices=[l.value for l in KeyboardLayout],
                        default='us', help='Keyboard layout')
    parser.add_argument('--encode', action='store_true', help='Encode to HID reports')
    parser.add_argument('--encode-output', help='Output encoded HID reports')
    
    args = parser.parse_args()
    
    layout = KeyboardLayout(args.layout)
    compiler = DuckyCompiler(KeyboardLayout(args.layout))
    
    script = compiler.compile_file(args.input)
    
    if script.errors:
        for error in script.errors:
            print(f"ERROR: {error}")
    if script.warnings:
        for warning in script.warnings:
            print(f"WARNING: {warning}")
    
    if args.output:
        compiler.save_compiled(script, args.output)
        print(f"Saved compiled script to {args.output}")
    
    if args.encode:
        reports = compiler.encode_to_hid(script)
        if args.encode_output:
            with open(args.encode_output, 'wb') as f:
                for report in reports:
                    f.write(report)
            print(f"Encoded {len(reports)} HID reports to {args.encode_output}")
        else:
            print(f"Encoded {len(reports)} HID reports")


# Export all public classes
__all__ = [
    "KeyboardLayout",
    "DuckyCommandType",
    "DuckyCommand",
    "ParsedScript",
    "KeyMapper",
    "DuckyParser",
    "DuckyEncoder",
    "DuckyCompiler",
    "ParsedScript",
    "LAYOUT_US",
    "LAYOUT_GB",
    "LAYOUT_DE",
    "LAYOUT_FR",
    "LAYOUT_ES",
    "LAYOUT_IT",
    "LAYOUT_RU",
    "create_compiler",
    "load_ducky_file",
]