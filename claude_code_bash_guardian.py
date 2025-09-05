#!/usr/bin/env python3
# Dependencies: bashlex, pyyaml
# Install with: pip install bashlex pyyaml

"""
Claude Code Bash Guardian - Automated Security Hook for Claude Code
Provides unattended bash command security through intelligent filtering and path control
"""

import json
import sys
import os
from pathlib import Path
import yaml
import bashlex
from datetime import datetime
from typing import List, Tuple, Optional, Dict, Any, Set
from dataclasses import dataclass
from abc import ABC, abstractmethod


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class CheckResult:
    """Result from a security check"""
    allowed: bool
    reason: Optional[str] = None
    
    @classmethod
    def allow(cls):
        return cls(allowed=True, reason="Check passed")
    
    @classmethod
    def deny(cls, reason: str):
        return cls(allowed=False, reason=reason)


@dataclass
class CommandContext:
    """Context for command analysis"""
    original_command: str
    ast_tree: List[Any]
    individual_commands: List[str]
    all_paths: List[str]
    all_arguments: List[str]
    project_root: str


# ============================================================================
# Configuration Management
# ============================================================================

class ConfigManager:
    """Manages configuration loading and access"""
    
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or (Path(__file__).parent / 'claude_code_bash_guardian_config.yaml')
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load and validate configuration"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                user_config = yaml.safe_load(f) or {}
        except Exception:
            user_config = {}
        
        # Default configuration
        defaults = {
            'forbidden_env_vars': [],
            'forbidden_pipe_targets': [],
            'multi_level_commands': [],
            'wrapper_commands': [
                'timeout', 'time', 'nice', 'nohup', 'strace', 'ltrace',
                'env', 'watch', 'xargs', 'parallel', 'caffeinate', 'unbuffer'
            ],
            'command_blacklist': [],
            'security_options': {
                'allow_external_path_access': False,
                'allow_variable_commands': False,
                'external_read_exception_commands': [],
                'external_copy_exception_commands': ['cp', 'ln', 'rsync']
            },
            'system_config': {
                'debug_mode': False,
                'log_denials': True,
                'log_approvals': True
            }
        }
        
        # Merge configurations
        return self._deep_merge(defaults, user_config)
    
    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        """Deep merge two dictionaries"""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config.get(key, default)
    
    def get_security_option(self, option: str, default: Any = None) -> Any:
        """Get security option value"""
        return self.config.get('security_options', {}).get(option, default)
    
    def get_system_config(self, option: str, default: Any = None) -> Any:
        """Get system configuration value"""
        return self.config.get('system_config', {}).get(option, default)


# ============================================================================
# Project Detection
# ============================================================================

class ProjectDetector:
    """Detects project root directory"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
    
    def detect_project_root(self) -> str:
        """Detect the project root directory"""
        # Skip detection if external access is allowed
        if self.config.get_security_option('allow_external_path_access', False):
            return str(Path.cwd())
        
        current = Path.cwd().resolve()
        return str(self._find_project_markers(current))
    
    def _find_project_markers(self, start_path: Path) -> Path:
        """Find project root based on markers"""
        current = start_path
        script_dir = Path(__file__).parent.resolve()
        home_dir = Path.home().resolve()
        
        found_claude_dirs = []
        found_git_dir = None
        
        # Traverse upward to collect information
        for path in [current] + list(current.parents):
            if path == home_dir or path == Path('/'):
                break
            
            if (path / '.claude').exists():
                found_claude_dirs.append(path)
            
            if found_git_dir is None and (path / '.git').exists():
                found_git_dir = path
        
        # Priority 1: Script under .claude directory
        for claude_root in found_claude_dirs:
            try:
                script_dir.relative_to(claude_root / '.claude')
                return claude_root
            except ValueError:
                continue
        
        # Priority 2: Outermost .claude directory
        if found_claude_dirs:
            return found_claude_dirs[-1]
        
        # Priority 3: .git directory
        if found_git_dir:
            return found_git_dir
        
        # Priority 4: Current directory
        return current


# ============================================================================
# AST Command Parser
# ============================================================================

class CommandParser:
    """Parses bash commands into structured data"""
    
    def parse(self, command: str, project_root: str) -> CommandContext:
        """Parse command and extract information"""
        if not command.strip():
            raise ValueError("Empty command")
        
        try:
            ast_tree = bashlex.parse(command)
        except Exception as e:
            raise ValueError(f"Command syntax error: {str(e)}")
        
        context = CommandContext(
            original_command=command,
            ast_tree=ast_tree,
            individual_commands=[],
            all_paths=[],
            all_arguments=[],
            project_root=project_root
        )
        
        # Extract information from AST
        self._extract_commands(ast_tree, context)
        self._extract_paths(ast_tree, context)
        self._extract_arguments(ast_tree, context)
        
        return context
    
    def _extract_commands(self, nodes: Any, context: CommandContext):
        """Extract individual commands from AST"""
        if isinstance(nodes, list):
            for node in nodes:
                self._extract_commands(node, context)
        elif hasattr(nodes, 'kind'):
            if nodes.kind == 'command' and hasattr(nodes, 'parts') and nodes.parts:
                cmd_parts = []
                for part in nodes.parts:
                    if part.kind == 'word':
                        text = context.original_command[part.pos[0]:part.pos[1]]
                        cmd_parts.append(text)
                if cmd_parts:
                    context.individual_commands.append(' '.join(cmd_parts))
            
            # Recurse into child nodes
            if hasattr(nodes, 'parts'):
                self._extract_commands(nodes.parts, context)
            if hasattr(nodes, 'list'):
                self._extract_commands(nodes.list, context)
    
    def _extract_paths(self, nodes: Any, context: CommandContext):
        """Extract all path-like arguments"""
        command_positions = set()
        self._collect_command_positions(nodes, command_positions, context)
        self._walk_for_paths(nodes, context, command_positions)
    
    def _collect_command_positions(self, nodes: Any, positions: Set, context: CommandContext):
        """Collect positions of command words"""
        if isinstance(nodes, list):
            for node in nodes:
                self._collect_command_positions(node, positions, context)
        elif hasattr(nodes, 'kind'):
            if nodes.kind == 'command' and hasattr(nodes, 'parts') and nodes.parts:
                if nodes.parts[0].kind == 'word':
                    positions.add((nodes.parts[0].pos[0], nodes.parts[0].pos[1]))
            
            if hasattr(nodes, 'parts'):
                self._collect_command_positions(nodes.parts, positions, context)
            if hasattr(nodes, 'list'):
                self._collect_command_positions(nodes.list, positions, context)
    
    def _walk_for_paths(self, nodes: Any, context: CommandContext, command_positions: Set):
        """Walk AST to extract paths"""
        if isinstance(nodes, list):
            for node in nodes:
                self._walk_for_paths(node, context, command_positions)
        elif hasattr(nodes, 'kind'):
            if nodes.kind == 'word' and (nodes.pos[0], nodes.pos[1]) not in command_positions:
                text = context.original_command[nodes.pos[0]:nodes.pos[1]]
                if any(text.startswith(p) for p in ['/', './', '../', '~/']):
                    context.all_paths.append(text)
            elif nodes.kind == 'redirect':
                if hasattr(nodes, 'output'):
                    self._walk_for_paths(nodes.output, context, command_positions)
                if hasattr(nodes, 'input'):
                    self._walk_for_paths(nodes.input, context, command_positions)
            
            if hasattr(nodes, 'parts'):
                self._walk_for_paths(nodes.parts, context, command_positions)
            if hasattr(nodes, 'list'):
                self._walk_for_paths(nodes.list, context, command_positions)
    
    def _extract_arguments(self, nodes: Any, context: CommandContext):
        """Extract all arguments"""
        if isinstance(nodes, list):
            for node in nodes:
                self._extract_arguments(node, context)
        elif hasattr(nodes, 'kind'):
            if nodes.kind == 'word':
                text = context.original_command[nodes.pos[0]:nodes.pos[1]]
                context.all_arguments.append(text)
            
            if hasattr(nodes, 'parts'):
                self._extract_arguments(nodes.parts, context)
            if hasattr(nodes, 'list'):
                self._extract_arguments(nodes.list, context)


# ============================================================================
# Security Check Base Class
# ============================================================================

class SecurityCheck(ABC):
    """Base class for security checks"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
    
    @abstractmethod
    def check(self, context: CommandContext) -> CheckResult:
        """Perform security check"""
        pass
    
    def normalize_command_path(self, cmd: str, project_root: str) -> str:
        """Normalize command path for consistent matching"""
        if '/' not in cmd:
            return cmd
        
        try:
            cmd_path = Path(cmd).resolve()
            project_path = Path(project_root).resolve()
            
            try:
                relative = cmd_path.relative_to(project_path)
                return str(relative)
            except ValueError:
                return cmd_path.name
        except:
            return cmd


# ============================================================================
# Individual Security Checks
# ============================================================================

class EnvironmentVariableCheck(SecurityCheck):
    """Check for forbidden environment variables"""
    
    def check(self, context: CommandContext) -> CheckResult:
        forbidden = self.config.get('forbidden_env_vars', [])
        if not forbidden:
            return CheckResult.allow()
        
        result = self._check_env_in_ast(context.ast_tree, forbidden, context)
        return result if result and not result.allowed else CheckResult.allow()
    
    def _check_env_in_ast(self, nodes: Any, forbidden: List[str], context: CommandContext) -> Optional[CheckResult]:
        """Check AST nodes for forbidden environment variables"""
        if isinstance(nodes, list):
            for node in nodes:
                result = self._check_env_in_ast(node, forbidden, context)
                if result and not result.allowed:
                    return result
        elif hasattr(nodes, 'kind'):
            # Check assignment nodes
            if nodes.kind == 'assignment' and hasattr(nodes, 'word'):
                if '=' in nodes.word:
                    var_name = nodes.word.split('=')[0].strip()
                    if var_name.upper() in [v.upper() for v in forbidden]:
                        return CheckResult.deny(f"Forbidden environment variable: {var_name}")
            
            # Check command nodes for env/export patterns
            if nodes.kind == 'command' and hasattr(nodes, 'parts') and nodes.parts:
                # Check for environment variable assignments before command
                for i, part in enumerate(nodes.parts):
                    if hasattr(part, 'word') and '=' in part.word and not part.word.startswith('-'):
                        var_name = part.word.split('=')[0]
                        if var_name.upper() in [v.upper() for v in forbidden]:
                            # Check if this is before the actual command
                            if i == 0 or all(hasattr(p, 'word') and '=' in p.word for p in nodes.parts[:i]):
                                return CheckResult.deny(f"Forbidden environment variable: {var_name}")
                
                # Check export/env commands
                if hasattr(nodes.parts[0], 'word'):
                    cmd = nodes.parts[0].word
                    if cmd in ['export', 'env']:
                        for part in nodes.parts[1:]:
                            if hasattr(part, 'word') and '=' in part.word:
                                var_name = part.word.split('=')[0]
                                if not var_name.startswith('-') and var_name.upper() in [v.upper() for v in forbidden]:
                                    return CheckResult.deny(f"Forbidden environment variable: {var_name}")
            
            # Recurse
            if hasattr(nodes, 'parts'):
                result = self._check_env_in_ast(nodes.parts, forbidden, context)
                if result and not result.allowed:
                    return result
            if hasattr(nodes, 'list'):
                result = self._check_env_in_ast(nodes.list, forbidden, context)
                if result and not result.allowed:
                    return result
        
        return None


class PipeSecurityCheck(SecurityCheck):
    """Check for dangerous pipe targets"""
    
    def check(self, context: CommandContext) -> CheckResult:
        forbidden = self.config.get('forbidden_pipe_targets', [])
        if not forbidden:
            return CheckResult.allow()
        
        result = self._check_pipes_in_ast(context.ast_tree, forbidden, context)
        return result if result and not result.allowed else CheckResult.allow()
    
    def _check_pipes_in_ast(self, nodes: Any, forbidden: List[str], context: CommandContext) -> Optional[CheckResult]:
        """Check AST for dangerous pipe targets"""
        if isinstance(nodes, list):
            for node in nodes:
                result = self._check_pipes_in_ast(node, forbidden, context)
                if result and not result.allowed:
                    return result
        elif hasattr(nodes, 'kind'):
            if nodes.kind == 'pipeline':
                # Check each command in the pipeline
                for part in nodes.parts:
                    if hasattr(part, 'kind') and part.kind == 'command':
                        if hasattr(part, 'parts') and part.parts:
                            first = part.parts[0]
                            if hasattr(first, 'word'):
                                cmd_name = self.normalize_command_path(first.word, context.project_root)
                                if cmd_name in forbidden:
                                    return CheckResult.deny(f"Dangerous pipe target: {cmd_name}")
            
            # Recurse
            if hasattr(nodes, 'parts'):
                result = self._check_pipes_in_ast(nodes.parts, forbidden, context)
                if result and not result.allowed:
                    return result
            if hasattr(nodes, 'list'):
                result = self._check_pipes_in_ast(nodes.list, forbidden, context)
                if result and not result.allowed:
                    return result
        
        return None


class VariableCommandCheck(SecurityCheck):
    """Check for variable command execution"""
    
    def check(self, context: CommandContext) -> CheckResult:
        if self.config.get_security_option('allow_variable_commands', False):
            return CheckResult.allow()
        
        result = self._check_variables_in_ast(context.ast_tree, context)
        return result if result and not result.allowed else CheckResult.allow()
    
    def _check_variables_in_ast(self, nodes: Any, context: CommandContext) -> Optional[CheckResult]:
        """Check AST for variable command execution"""
        if isinstance(nodes, list):
            for node in nodes:
                result = self._check_variables_in_ast(node, context)
                if result and not result.allowed:
                    return result
        elif hasattr(nodes, 'kind'):
            if nodes.kind == 'command' and hasattr(nodes, 'parts') and nodes.parts:
                first = nodes.parts[0]
                
                # Check for parameter expansion or command substitution in command position
                if hasattr(first, 'parts'):
                    for subpart in first.parts:
                        if hasattr(subpart, 'kind'):
                            if subpart.kind in ['parameter', 'commandsubstitution']:
                                return CheckResult.deny("Variable command execution not allowed")
                
                # Check for eval and similar commands
                if hasattr(first, 'word'):
                    word = first.word
                    if word == 'eval':
                        return CheckResult.deny("Dynamic command execution not allowed")
                    
                    # Check source commands
                    if word in ['.', 'source', 'command', 'exec']:
                        if len(nodes.parts) > 1:
                            next_part = nodes.parts[1]
                            if hasattr(next_part, 'parts'):
                                for subpart in next_part.parts:
                                    if hasattr(subpart, 'kind') and subpart.kind in ['parameter', 'commandsubstitution']:
                                        return CheckResult.deny("Variable command execution not allowed")
                    
                    # Check wrapper commands
                    wrappers = self.config.get('wrapper_commands', [])
                    if word in wrappers:
                        for part in nodes.parts[1:]:
                            if hasattr(part, 'parts'):
                                for subpart in part.parts:
                                    if hasattr(subpart, 'kind') and subpart.kind in ['parameter', 'commandsubstitution']:
                                        if hasattr(part, 'word') and not part.word.startswith('-'):
                                            return CheckResult.deny("Variable command execution not allowed")
                                            break
            
            # Recurse
            if hasattr(nodes, 'parts'):
                result = self._check_variables_in_ast(nodes.parts, context)
                if result and not result.allowed:
                    return result
            if hasattr(nodes, 'list'):
                result = self._check_variables_in_ast(nodes.list, context)
                if result and not result.allowed:
                    return result
        
        return None


class BlacklistCheck(SecurityCheck):
    """Check against command blacklist"""
    
    def check(self, context: CommandContext) -> CheckResult:
        blacklist = self.config.get('command_blacklist', [])
        wrappers = set(self.config.get('wrapper_commands', []))
        
        for cmd in context.individual_commands:
            for pattern in blacklist:
                if self._matches_pattern(cmd, pattern, wrappers, context.project_root):
                    return CheckResult.deny(f"Blacklisted command pattern: {pattern}")
        
        return CheckResult.allow()
    
    def _matches_pattern(self, command: str, pattern: str, wrappers: Set[str], project_root: str) -> bool:
        """Check if command matches blacklist pattern"""
        pattern_parts = pattern.split()
        cmd_parts = command.split()
        
        if not cmd_parts or not pattern_parts:
            return False
        
        # Check if first command is a wrapper
        first_cmd = cmd_parts[0]
        first_basename = Path(first_cmd).name if '/' in first_cmd else first_cmd
        is_wrapper = first_basename in wrappers
        
        # Direct matching for non-wrappers
        if not is_wrapper:
            return self._check_at_position(cmd_parts, pattern_parts, 0, project_root)
        
        # Scanning strategy for wrappers
        if self._check_at_position(cmd_parts, pattern_parts, 0, project_root):
            return True
        
        # Scan for pattern in arguments
        if len(pattern_parts) == 1:
            pattern_cmd = pattern_parts[0]
            for part in cmd_parts[1:]:
                normalized = self.normalize_command_path(part, project_root)
                if normalized == pattern_cmd:
                    return True
        else:
            pattern_cmd = pattern_parts[0]
            pattern_args = pattern_parts[1:]
            for i, part in enumerate(cmd_parts[1:], 1):
                normalized = self.normalize_command_path(part, project_root)
                if normalized == pattern_cmd:
                    if self._check_arguments(cmd_parts[i+1:], pattern_args):
                        return True
        
        return False
    
    def _check_at_position(self, cmd_parts: List[str], pattern_parts: List[str], 
                          pos: int, project_root: str) -> bool:
        """Check if pattern matches at specific position"""
        if pos >= len(cmd_parts):
            return False
        
        pattern_cmd = pattern_parts[0]
        actual_cmd = self.normalize_command_path(cmd_parts[pos], project_root)
        
        if actual_cmd != pattern_cmd:
            return False
        
        if len(pattern_parts) == 1:
            return True
        
        return self._check_arguments(cmd_parts[pos+1:], pattern_parts[1:])
    
    def _check_arguments(self, args: List[str], pattern_args: List[str]) -> bool:
        """Check if arguments match pattern"""
        for pattern_arg in pattern_args:
            if pattern_arg.startswith('--'):
                if pattern_arg not in args:
                    return False
            elif pattern_arg.startswith('-'):
                pattern_chars = set(pattern_arg[1:])
                found_chars = set()
                for arg in args:
                    if arg.startswith('-') and not arg.startswith('--'):
                        found_chars.update(arg[1:])
                if not pattern_chars.issubset(found_chars):
                    return False
            else:
                if pattern_arg not in args:
                    return False
        return True


class PathAccessCheck(SecurityCheck):
    """Check path access control"""
    
    # Special /dev files that are always allowed
    ALLOWED_DEV_FILES = {
        '/dev/null', '/dev/stdout', '/dev/stderr', '/dev/stdin',
        '/dev/zero', '/dev/urandom', '/dev/random', '/dev/tty'
    }
    
    def check(self, context: CommandContext) -> CheckResult:
        if self.config.get_security_option('allow_external_path_access', False):
            return CheckResult.allow()
        
        # Count external paths
        external_paths = [p for p in context.all_paths if self._is_external(p, context.project_root)]
        external_count = len(external_paths)
        
        if external_count == 0:
            return CheckResult.allow()
        
        # Count allowed external accesses
        allowed_count = 0
        allowed_count += self._count_read_exceptions(context)
        allowed_count += self._count_copy_exceptions(context)
        
        # Check balance
        if external_count == allowed_count:
            return CheckResult.allow()
        
        return CheckResult.deny(self._build_error_message())
    
    def _is_external(self, path: str, project_root: str) -> bool:
        """Check if path is external to project"""
        # Check special /dev files
        if path in self.ALLOWED_DEV_FILES or path.startswith('/dev/fd/'):
            return False
        
        try:
            # Expand and resolve path
            if path.startswith('~/'):
                expanded = os.path.expanduser(path)
                target = Path(expanded).resolve()
            else:
                target = Path(path).resolve()
            
            project = Path(project_root).resolve()
            
            # Check if in project
            try:
                target.relative_to(project)
                return False
            except ValueError:
                pass
            
            # Check if in /tmp
            try:
                target.relative_to(Path('/tmp').resolve())
                return False
            except ValueError:
                pass
            
            return True
        except:
            return True
    
    def _count_read_exceptions(self, context: CommandContext) -> int:
        """Count external paths used by read exception commands"""
        read_cmds = self.config.get_security_option('external_read_exception_commands', [])
        count = 0
        
        for cmd in context.individual_commands:
            parts = cmd.split()
            if parts:
                cmd_name = Path(parts[0]).name if '/' in parts[0] else parts[0]
                if cmd_name in read_cmds:
                    for arg in parts[1:]:
                        if not arg.startswith('-') and self._is_external(arg, context.project_root):
                            count += 1
        
        return count
    
    def _count_copy_exceptions(self, context: CommandContext) -> int:
        """Count external source paths in copy commands"""
        copy_cmds = self.config.get_security_option('external_copy_exception_commands', [])
        count = 0
        
        for cmd in context.individual_commands:
            parts = cmd.split()
            if len(parts) >= 3:
                cmd_name = Path(parts[0]).name if '/' in parts[0] else parts[0]
                if cmd_name in copy_cmds:
                    # All except last are sources
                    for src in parts[1:-1]:
                        if not src.startswith('-') and self._is_external(src, context.project_root):
                            count += 1
        
        return count
    
    def _build_error_message(self) -> str:
        """Build helpful error message"""
        read_cmds = self.config.get_security_option('external_read_exception_commands', [])
        copy_cmds = self.config.get_security_option('external_copy_exception_commands', [])
        
        if not read_cmds and not copy_cmds:
            return "External path access not allowed"
        
        parts = []
        if read_cmds:
            parts.append(f"READ: {', '.join(read_cmds)}")
        if copy_cmds:
            parts.append(f"COPY-FROM: {', '.join(copy_cmds)}")
        
        msg = f"External path access not allowed. Allowed commands for external paths: {' | '.join(parts)}."
        msg += " To access external files, first copy them to project directory or /tmp using allowed commands."
        return msg


# ============================================================================
# Logging
# ============================================================================

class Logger:
    """Handles logging of security decisions"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.log_dir = Path(__file__).parent / 'logs'
        self.log_dir.mkdir(exist_ok=True)
    
    def log_decision(self, command: str, allowed: bool, reason: str, project_root: str):
        """Log a security decision"""
        should_log = self.config.get_system_config(
            'log_approvals' if allowed else 'log_denials',
            not allowed  # Default: log denials
        )
        
        if not should_log:
            return
        
        entry = {
            'timestamp': datetime.now().isoformat(),
            'command': command,
            'action': 'approved' if allowed else 'rejected',
            'reason': reason,
            'runtime_dir': project_root
        }
        
        filename = 'permission_approvals.json' if allowed else 'permission_denials.json'
        log_file = self.log_dir / filename
        
        # Load existing logs
        if log_file.exists():
            try:
                with open(log_file, 'r') as f:
                    logs = json.load(f)
            except:
                logs = []
        else:
            logs = []
        
        logs.append(entry)
        
        # Keep only last 100 entries
        if len(logs) > 100:
            logs = logs[-100:]
        
        with open(log_file, 'w') as f:
            json.dump(logs, f, indent=2)


# ============================================================================
# Main Guardian Class
# ============================================================================

class ClaudeBashGuardian:
    """Main security guardian orchestrator"""
    
    def __init__(self):
        self.config = ConfigManager()
        self.project_detector = ProjectDetector(self.config)
        self.parser = CommandParser()
        self.logger = Logger(self.config)
        
        # Initialize security checks
        self.checks = [
            EnvironmentVariableCheck(self.config),
            PipeSecurityCheck(self.config),
            VariableCommandCheck(self.config),
            BlacklistCheck(self.config),
            PathAccessCheck(self.config)
        ]
        
        # Cache project root
        self.runtime_dir = self.project_detector.detect_project_root()
    
    def check_permission(self, tool_input: Dict[str, Any]) -> Tuple[bool, str]:
        """Check if command is allowed"""
        command = tool_input.get('command', '')
        if not command:
            return True, "Empty command"
        
        # Parse command
        try:
            context = self.parser.parse(command, self.runtime_dir)
        except ValueError as e:
            return False, f"Command syntax error detected by bashlex: {str(e)}"
        
        # Run security checks
        for check in self.checks:
            result = check.check(context)
            if not result.allowed:
                return False, result.reason
        
        return True, "All checks passed"
    
    def _log_action(self, tool_input: Dict[str, Any], is_allowed: bool, reason: str):
        """Log the security decision"""
        command = tool_input.get('command', '')
        self.logger.log_decision(command, is_allowed, reason, self.runtime_dir)


# ============================================================================
# Entry Point
# ============================================================================

def main():
    """Main entry function"""
    try:
        # Read JSON input
        input_data = json.load(sys.stdin)
        tool_input = input_data.get('tool_input', {})
        
        # Create guardian
        guardian = ClaudeBashGuardian()
        
        # Debug output
        if guardian.config.get_system_config('debug_mode', False):
            print(f"DEBUG: Project root directory: {guardian.runtime_dir}", file=sys.stderr)
            print(f"DEBUG: Current working directory: {os.getcwd()}", file=sys.stderr)
            print(f"DEBUG: Command: {tool_input.get('command', '')}", file=sys.stderr)
        
        # Check permission
        is_allowed, reason = guardian.check_permission(tool_input)
        
        # Log decision
        guardian._log_action(tool_input, is_allowed, reason)
        
        # Return response
        response = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow" if is_allowed else "deny",
                "permissionDecisionReason": reason if is_allowed else f"Command blocked by security policy: {reason}"
            }
        }
        
        print(json.dumps(response))
        sys.exit(0 if is_allowed else 2)
    
    except Exception as e:
        # On error, allow execution
        print(f"Hook execution error: {str(e)}", file=sys.stderr)
        sys.exit(0)


if __name__ == '__main__':
    main()
