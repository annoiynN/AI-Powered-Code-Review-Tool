"""
error_detector.py - Module for detecting potential errors and issues in source code.

This module is responsible for:
1. Detecting syntax errors
2. Identifying common programming mistakes
3. Finding potential bugs and logical issues
4. Detecting code style violations
5. Identifying security vulnerabilities
"""

import ast
import re
import logging
from typing import Dict, List, Any, Union, Set, Tuple, Optional
import os

# Import the code parser module
from backend.code_parser import CodeParser

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ErrorCategory:
    """Constants for error categories."""
    SYNTAX = "syntax"
    SECURITY = "security"
    PERFORMANCE = "performance"
    STYLE = "style"
    LOGIC = "logic"
    BEST_PRACTICE = "best_practice"
    
class ErrorSeverity:
    """Constants for error severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class CodeError:
    """Class representing a detected error or issue in code."""
    
    def __init__(
        self,
        code: str,
        message: str,
        line_start: int,
        line_end: Optional[int] = None,
        column_start: Optional[int] = None,
        column_end: Optional[int] = None,
        category: str = ErrorCategory.LOGIC,
        severity: str = ErrorSeverity.MEDIUM,
        suggestion: Optional[str] = None,
        affected_code: Optional[str] = None
    ):
        """
        Initialize a code error.
        
        Args:
            code: Error code identifier
            message: Human-readable error message
            line_start: Line number where the error starts (1-based)
            line_end: Line number where the error ends (optional)
            column_start: Column number where the error starts (optional)
            column_end: Column number where the error ends (optional)
            category: Error category (syntax, security, etc.)
            severity: Error severity level
            suggestion: Suggested fix or improvement
            affected_code: The problematic code snippet
        """
        self.code = code
        self.message = message
        self.line_start = line_start
        self.line_end = line_end or line_start
        self.column_start = column_start
        self.column_end = column_end
        self.category = category
        self.severity = severity
        self.suggestion = suggestion
        self.affected_code = affected_code
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the error to a dictionary representation."""
        return {
            "code": self.code,
            "message": self.message,
            "location": {
                "line_start": self.line_start,
                "line_end": self.line_end,
                "column_start": self.column_start,
                "column_end": self.column_end
            },
            "category": self.category,
            "severity": self.severity,
            "suggestion": self.suggestion,
            "affected_code": self.affected_code
        }

class ErrorDetector:
    """Main class for detecting errors in source code."""
    
    def __init__(self):
        """Initialize the error detector."""
        self.parser = CodeParser()
        self.current_file = None
        self.current_language = None
        self.parsed_code = None
        self.code_lines = []
        
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze a source code file for errors and issues.
        
        Args:
            file_path: Path to the source code file
            
        Returns:
            Dictionary containing analysis results with detected errors
        """
        try:
            self.current_file = file_path
            
            # Parse the file
            self.parsed_code = self.parser.parse_file(file_path)
            
            if not self.parsed_code.get("success", False):
                return {
                    "success": False,
                    "file_path": file_path,
                    "errors": [self._create_parsing_error(self.parsed_code.get("error", "Unknown parsing error"))]
                }
                
            self.code_lines = self.parsed_code.get("code_lines", [])
            self.current_language = self.parsed_code.get("language")
            
            # Detect errors based on the language
            errors = []
            
            if self.current_language == "python":
                errors.extend(self._detect_python_errors())
            elif self.current_language == "javascript":
                errors.extend(self._detect_javascript_errors())
            elif self.current_language in ["java", "csharp", "c", "cpp"]:
                errors.append(CodeError(
                    "UNSUPPORTED_LANGUAGE",
                    f"Full error detection for {self.current_language} not implemented yet",
                    1,
                    category=ErrorCategory.INFO,
                    severity=ErrorSeverity.INFO
                ))
            
            # Common detectors that work across languages
            errors.extend(self._detect_common_issues())
            
            return {
                "success": True,
                "file_path": file_path,
                "language": self.current_language,
                "errors": [error.to_dict() for error in errors],
                "error_count": len(errors),
                "error_summary": self._summarize_errors(errors)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {str(e)}")
            return {
                "success": False,
                "file_path": file_path,
                "errors": [self._create_exception_error(e)]
            }
    
    def _create_parsing_error(self, error_message: str) -> Dict[str, Any]:
        """Create a standardized error for parsing failures."""
        return CodeError(
            "PARSE_ERROR",
            f"Failed to parse file: {error_message}",
            1,
            category=ErrorCategory.SYNTAX,
            severity=ErrorSeverity.CRITICAL
        ).to_dict()
    
    def _create_exception_error(self, exception: Exception) -> Dict[str, Any]:
        """Create a standardized error for exceptions during analysis."""
        return CodeError(
            "ANALYSIS_ERROR",
            f"Error during analysis: {str(exception)}",
            1,
            category=ErrorCategory.SYNTAX,
            severity=ErrorSeverity.CRITICAL
        ).to_dict()
    
    def _summarize_errors(self, errors: List[CodeError]) -> Dict[str, int]:
        """
        Summarize errors by category and severity.
        
        Args:
            errors: List of detected errors
            
        Returns:
            Dictionary with error counts by category and severity
        """
        by_category = {}
        by_severity = {}
        
        for error in errors:
            # Count by category
            if error.category not in by_category:
                by_category[error.category] = 0
            by_category[error.category] += 1
            
            # Count by severity
            if error.severity not in by_severity:
                by_severity[error.severity] = 0
            by_severity[error.severity] += 1
        
        return {
            "by_category": by_category,
            "by_severity": by_severity,
            "total": len(errors)
        }
            
    def _detect_python_errors(self) -> List[CodeError]:
        """
        Detect errors in Python code.
        
        Returns:
            List of detected errors
        """
        errors = []
        
        # If we have an AST, perform static analysis
        if "ast" in self.parsed_code and self.parsed_code["ast"]:
            ast_tree = self.parsed_code["ast"]
            errors.extend(self._detect_python_syntax_errors(ast_tree))
            errors.extend(self._detect_python_common_mistakes(ast_tree))
            errors.extend(self._detect_python_security_issues(ast_tree))
            errors.extend(self._detect_python_best_practices(ast_tree))
        
        # If there was a syntax error during parsing
        if "syntax_error" in self.parsed_code:
            error_info = self.parsed_code["syntax_error"]
            errors.append(CodeError(
                "PY_SYNTAX_ERROR",
                f"Python syntax error: {error_info['msg']}",
                error_info["line"],
                column_start=error_info["column"],
                category=ErrorCategory.SYNTAX,
                severity=ErrorSeverity.CRITICAL,
                affected_code=error_info["text"]
            ))
            
        return errors
    
    def _detect_python_syntax_errors(self, ast_tree: ast.AST) -> List[CodeError]:
        """
        Detect Python syntax errors and issues.
        
        Args:
            ast_tree: Python AST
            
        Returns:
            List of syntax errors
        """
        errors = []
        
        # Check for undefined variables (simplified)
        defined_vars = set()
        
        class VarCollector(ast.NodeVisitor):
            def visit_Name(self, node):
                if isinstance(node.ctx, ast.Store):
                    defined_vars.add(node.id)
                self.generic_visit(node)
                
            def visit_FunctionDef(self, node):
                # Add function name and arguments to defined vars
                defined_vars.add(node.name)
                for arg in node.args.args:
                    defined_vars.add(arg.arg)
                self.generic_visit(node)
                
            def visit_ClassDef(self, node):
                # Add class name to defined vars
                defined_vars.add(node.name)
                self.generic_visit(node)
                
            def visit_Import(self, node):
                # Add imported modules to defined vars
                for name in node.names:
                    if name.asname:
                        defined_vars.add(name.asname)
                    else:
                        defined_vars.add(name.name.split('.')[0])
                self.generic_visit(node)
                
            def visit_ImportFrom(self, node):
                # Add imported names to defined vars
                for name in node.names:
                    if name.asname:
                        defined_vars.add(name.asname)
                    else:
                        defined_vars.add(name.name)
                self.generic_visit(node)
        
        # Collect defined variables
        collector = VarCollector()
        collector.visit(ast_tree)
        
        # Check for undefined variables
        class UndefinedVarChecker(ast.NodeVisitor):
            def visit_Name(self, node):
                if isinstance(node.ctx, ast.Load) and node.id not in defined_vars and node.id not in dir(__builtins__):
                    errors.append(CodeError(
                        "PY_UNDEFINED_VAR",
                        f"Potentially undefined variable: {node.id}",
                        node.lineno,
                        category=ErrorCategory.LOGIC,
                        severity=ErrorSeverity.HIGH,
                        suggestion=f"Make sure '{node.id}' is defined before use or check for typos."
                    ))
                self.generic_visit(node)
        
        # Check for undefined variables
        undefined_checker = UndefinedVarChecker()
        undefined_checker.visit(ast_tree)
        
        return errors
    
    def _detect_python_common_mistakes(self, ast_tree: ast.AST) -> List[CodeError]:
        """
        Detect common Python mistakes.
        
        Args:
            ast_tree: Python AST
            
        Returns:
            List of detected common mistakes
        """
        errors = []
        
        # Check for mutable default arguments
        class MutableDefaultChecker(ast.NodeVisitor):
            def visit_FunctionDef(self, node):
                for i, default in enumerate(node.args.defaults):
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        arg_idx = len(node.args.args) - len(node.args.defaults) + i
                        if arg_idx < len(node.args.args):
                            arg_name = node.args.args[arg_idx].arg
                            errors.append(CodeError(
                                "PY_MUTABLE_DEFAULT",
                                f"Mutable default argument: {arg_name}",
                                node.lineno,
                                category=ErrorCategory.LOGIC,
                                severity=ErrorSeverity.MEDIUM,
                                suggestion="Use None as default and initialize the mutable value inside the function."
                            ))
                self.generic_visit(node)
        
        # Check for mutable defaults
        mutable_checker = MutableDefaultChecker()
        mutable_checker.visit(ast_tree)
        
        # Check for hardcoded file paths
        class HardcodedPathChecker(ast.NodeVisitor):
            def visit_Str(self, node):
                # Check if string looks like a file path
                if '/' in node.s or '\\' in node.s:
                    if node.s.startswith('/') or (len(node.s) > 1 and node.s[1] == ':'):
                        errors.append(CodeError(
                            "PY_HARDCODED_PATH",
                            f"Hardcoded file path: {node.s}",
                            node.lineno,
                            category=ErrorCategory.BEST_PRACTICE,
                            severity=ErrorSeverity.LOW,
                            suggestion="Consider using path configuration or environment variables."
                        ))
                self.generic_visit(node)
                
            # For Python 3.8+
            def visit_Constant(self, node):
                if isinstance(node.value, str):
                    # Check if string looks like a file path
                    if '/' in node.value or '\\' in node.value:
                        if node.value.startswith('/') or (len(node.value) > 1 and node.value[1] == ':'):
                            errors.append(CodeError(
                                "PY_HARDCODED_PATH",
                                f"Hardcoded file path: {node.value}",
                                node.lineno,
                                category=ErrorCategory.BEST_PRACTICE,
                                severity=ErrorSeverity.LOW,
                                suggestion="Consider using path configuration or environment variables."
                            ))
                self.generic_visit(node)
        
        # Check for hardcoded paths
        path_checker = HardcodedPathChecker()
        path_checker.visit(ast_tree)
        
        # Check for bare except clauses
        class BareExceptChecker(ast.NodeVisitor):
            def visit_ExceptHandler(self, node):
                if node.type is None:
                    errors.append(CodeError(
                        "PY_BARE_EXCEPT",
                        "Bare except clause",
                        node.lineno,
                        category=ErrorCategory.BEST_PRACTICE,
                        severity=ErrorSeverity.MEDIUM,
                        suggestion="Specify the exceptions you want to catch instead of using a bare except."
                    ))
                self.generic_visit(node)
        
        # Check for bare excepts
        except_checker = BareExceptChecker()
        except_checker.visit(ast_tree)
        
        return errors
    
    def _detect_python_security_issues(self, ast_tree: ast.AST) -> List[CodeError]:
        """
        Detect security issues in Python code.
        
        Args:
            ast_tree: Python AST
            
        Returns:
            List of detected security issues
        """
        errors = []
        
        # Check for potentially insecure function calls
        insecure_functions = {
            'eval': "Potentially dangerous use of eval()",
            'exec': "Potentially dangerous use of exec()",
            'pickle.loads': "Insecure use of pickle.loads() with untrusted data",
            'subprocess.call': "Potential command injection vulnerability in subprocess.call",
            'subprocess.Popen': "Potential command injection vulnerability in subprocess.Popen",
            'os.system': "Potential command injection vulnerability in os.system",
            'os.popen': "Potential command injection vulnerability in os.popen",
        }
        
        class SecurityChecker(ast.NodeVisitor):
            def visit_Call(self, node):
                func_name = None
                
                # Get the function name
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        func_name = f"{node.func.value.id}.{node.func.attr}"
                
                # Check if it's an insecure function
                if func_name in insecure_functions:
                    errors.append(CodeError(
                        "PY_SECURITY_RISK",
                        insecure_functions[func_name],
                        node.lineno,
                        category=ErrorCategory.SECURITY,
                        severity=ErrorSeverity.HIGH,
                        suggestion="Review use of this function, especially with user-provided input."
                    ))
                
                # Check for SQL injection vulnerability
                if isinstance(node.func, ast.Attribute) and node.func.attr in ['execute', 'executemany']:
                    # Simple check for string formatting in SQL
                    for arg in node.args:
                        if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
                            errors.append(CodeError(
                                "PY_SQL_INJECTION",
                                "Potential SQL injection vulnerability",
                                node.lineno,
                                category=ErrorCategory.SECURITY,
                                severity=ErrorSeverity.HIGH,
                                suggestion="Use parameterized queries instead of string formatting/concatenation."
                            ))
                
                self.generic_visit(node)
        
        # Check for security issues
        security_checker = SecurityChecker()
        security_checker.visit(ast_tree)
        
        return errors
    
    def _detect_python_best_practices(self, ast_tree: ast.AST) -> List[CodeError]:
        """
        Detect Python best practice violations.
        
        Args:
            ast_tree: Python AST
            
        Returns:
            List of best practice violations
        """
        errors = []
        
        # Check for missing docstrings
        class DocstringChecker(ast.NodeVisitor):
            def visit_Module(self, node):
                if not ast.get_docstring(node):
                    errors.append(CodeError(
                        "PY_NO_MODULE_DOCSTRING",
                        "Missing module docstring",
                        1,
                        category=ErrorCategory.STYLE,
                        severity=ErrorSeverity.LOW,
                        suggestion="Add a module-level docstring at the beginning of the file."
                    ))
                self.generic_visit(node)
                
            def visit_ClassDef(self, node):
                if not ast.get_docstring(node):
                    errors.append(CodeError(
                        "PY_NO_CLASS_DOCSTRING",
                        f"Missing docstring for class '{node.name}'",
                        node.lineno,
                        category=ErrorCategory.STYLE,
                        severity=ErrorSeverity.LOW,
                        suggestion=f"Add a docstring for class '{node.name}'."
                    ))
                self.generic_visit(node)
                
            def visit_FunctionDef(self, node):
                # Skip dunder methods (__init__ etc.) for docstring checks
                if not node.name.startswith('__') and not ast.get_docstring(node):
                    errors.append(CodeError(
                        "PY_NO_FUNCTION_DOCSTRING",
                        f"Missing docstring for function '{node.name}'",
                        node.lineno,
                        category=ErrorCategory.STYLE,
                        severity=ErrorSeverity.LOW,
                        suggestion=f"Add a docstring for function '{node.name}'."
                    ))
                self.generic_visit(node)
        
        # Check for missing docstrings
        docstring_checker = DocstringChecker()
        docstring_checker.visit(ast_tree)
        
        # Check for overly complex functions (too many statements)
        class ComplexityChecker(ast.NodeVisitor):
            def visit_FunctionDef(self, node):
                statement_count = sum(1 for _ in ast.walk(node) if isinstance(_, (ast.stmt)))
                if statement_count > 50:  # Arbitrary threshold
                    errors.append(CodeError(
                        "PY_COMPLEX_FUNCTION",
                        f"Function '{node.name}' is too complex ({statement_count} statements)",
                        node.lineno,
                        category=ErrorCategory.BEST_PRACTICE,
                        severity=ErrorSeverity.MEDIUM,
                        suggestion=f"Consider breaking function '{node.name}' into smaller, more focused functions."
                    ))
                self.generic_visit(node)
        
        # Check for complex functions
        complexity_checker = ComplexityChecker()
        complexity_checker.visit(ast_tree)
        
        return errors
    
    def _detect_javascript_errors(self) -> List[CodeError]:
        """
        Detect errors in JavaScript code.
        
        Returns:
            List of detected errors
        """
        # This is a simplified implementation. In a real-world application,
        # you would use a proper JavaScript parser and linter.
        errors = []
        
        # Very basic pattern-based detections
        js_patterns = [
            (r'console\.log\(', "PY_CONSOLE_LOG", "Console log statement in production code", 
             ErrorCategory.BEST_PRACTICE, ErrorSeverity.LOW, 
             "Remove console.log statements from production code."),
            
            (r'alert\(', "JS_ALERT", "Alert statement in code", 
             ErrorCategory.BEST_PRACTICE, ErrorSeverity.LOW, 
             "Consider using a more user-friendly notification system."),
            
            (r'eval\(', "JS_EVAL", "Potentially dangerous use of eval()", 
             ErrorCategory.SECURITY, ErrorSeverity.HIGH, 
             "Avoid using eval() as it can lead to security vulnerabilities."),
            
            (r'==(?!=)', "JS_LOOSE_EQUALITY", "Use of loose equality (==) instead of strict equality (===)", 
             ErrorCategory.BEST_PRACTICE, ErrorSeverity.LOW, 
             "Use === for comparison instead of == to avoid type coercion issues."),
        ]
        
        if not hasattr(self.parser, 'code_lines') or not self.parser.code_lines:
            return errors
            
        for i, line in enumerate(self.parser.code_lines):
            for pattern, code, message, category, severity, suggestion in js_patterns:
                if re.search(pattern, line):
                    errors.append(CodeError(
                        code,
                        message,
                        i + 1,  # 1-based line numbering
                        category=category,
                        severity=severity,
                        suggestion=suggestion,
                        affected_code=line.strip()
                    ))
        
        return errors
    
    def _detect_common_issues(self) -> List[CodeError]:
        """
        Detect issues common to all programming languages.
        
        Returns:
            List of detected common issues
        """
        errors = []
        
        # Check for lines that are too long
        if hasattr(self.parser, 'code_lines') and self.parser.code_lines:
            for i, line in enumerate(self.parser.code_lines):
                if len(line) > 100:  # Arbitrary threshold
                    errors.append(CodeError(
                        "COMMON_LONG_LINE",
                        f"Line too long ({len(line)} characters)",
                        i + 1,  # 1-based line numbering
                        category=ErrorCategory.STYLE,
                        severity=ErrorSeverity.LOW,
                        suggestion="Consider breaking the line into multiple lines for better readability.",
                        affected_code=line.strip()
                    ))
        
        # Check for TODO comments
        if hasattr(self.parser, 'code_lines') and self.parser.code_lines:
            for i, line in enumerate(self.parser.code_lines):
                if "TODO" in line or "FIXME" in line:
                    errors.append(CodeError(
                        "COMMON_TODO",
                        "TODO or FIXME comment found",
                        i + 1,  # 1-based line numbering
                        category=ErrorCategory.INFO,
                        severity=ErrorSeverity.INFO,
                        affected_code=line.strip()
                    ))
        
        return errors
    
    def analyze_directory(self, directory_path: str) -> Dict[str, Dict[str, Any]]:
        """
        Analyze all source code files in a directory.
        
        Args:
            directory_path: Path to the directory containing source files
            
        Returns:
            Dictionary mapping file paths to their analysis results
        """
        results = {}
        
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                _, ext = os.path.splitext(file_path)
                
                # Check if the file has a supported extension
                supported = False
                for exts in CodeParser.SUPPORTED_LANGUAGES.values():
                    if ext in exts:
                        supported = True
                        break
                        
                if supported:
                    results[file_path] = self.analyze_file(file_path)
                    
        return results

if __name__ == "__main__":
    # Example usage
    detector = ErrorDetector()
    
    # Example Python code with some issues
    sample_code = """
# This is a sample Python file with some issues
import os
import pickle

def process_data(data, output_file="output.txt", cache=[]):
    result = eval(data)  # Security risk: using eval
    
    # Store result in cache
    cache.append(result)
    
    with open(output_file, "w") as f:
        f.write(str(result))
    
    try:
        # Some code here
        pass
    except:  # Bare except
        print("An error occurred")
    
    return result

if name == "__main__":  # Undefined variable (missing underscore)
    user_input = input("Enter data: ")
    process_data(user_input)
"""
    
    # Create a temporary file for testing
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.py', mode='w+', delete=False) as f:
        f.write(sample_code)
        temp_file = f.name
    
    try:
        # Analyze the file and print results
        result = detector.analyze_file(temp_file)
        print("Analysis result:")
        
        if result["success"]:
            print(f"Found {result['error_count']} issues:")
            for error in result["errors"]:
                print(f"  - Line {error['location']['line_start']}: {error['message']} ({error['severity']})")
                if error.get("suggestion"):
                    print(f"    Suggestion: {error['suggestion']}")
                print()
    finally:
        # Clean up
        os.unlink(temp_file)