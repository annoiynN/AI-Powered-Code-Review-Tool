import ast
import re
import logging
import tempfile
from typing import Dict, List, Any, Union, Set, Tuple, Optional
import os
import subprocess


# Import the code parser module 
from backend.code_parser import CodeParser
from backend.models import ErrorDetail, CodeError as PydanticCodeError, RecommendationDetail, CodeStructureDetail


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
        type: str,  
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

        self.type = type
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
            "type": self.type,
            "message": self.message,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "column_start": self.column_start,
            "column_end": self.column_end,
            "category": self.category,
            "severity": self.severity,
            "suggestion": self.suggestion,
            "affected_code": self.affected_code
        }
    
    def to_pydantic_model(self) -> PydanticCodeError:
        """Convert the error to a Pydantic model."""
        return PydanticCodeError(
            type=self.type,
            message=self.message,
            line_start=self.line_start,
            line_end=self.line_end,
            column_start=self.column_start,
            column_end=self.column_end,
            category=self.category,
            severity=self.severity,
            suggestion=self.suggestion,
            affected_code=self.affected_code
        )


class ErrorDetector:
    def __init__(self):
        self.parser = CodeParser()
        self.current_file = None
        self.current_language = None
        self.parsed_code = None
        self.code_lines = []

    def detect_pattern_errors(self, code: str = None, language: str = None) -> List[CodeError]:
        if language is None:
            language = self.current_language if hasattr(self, 'current_language') else "python"
        if code is None:
            code = self.code_lines if hasattr(self, 'code_lines') else []

        errors = []

        patterns = {
            "python": [
                (r'print\s*\(', "PY_PRINT_DEBUG", "Print statement in production code",
                 ErrorCategory.BEST_PRACTICE, ErrorSeverity.LOW,
                 "Consider using proper logging instead of print statements."),

                (r'(?<![\'"])password\s*=\s*[\'"][^\'"]+[\'"]', "PY_HARDCODED_PASSWORD",
                 "Hardcoded password detected",
                 ErrorCategory.SECURITY, ErrorSeverity.HIGH,
                 "Never hardcode passwords, use environment variables or secure vaults."),

                (r'os\.system\(', "PY_OS_SYSTEM", "Potential command injection vulnerability",
                 ErrorCategory.SECURITY, ErrorSeverity.HIGH,
                 "Use subprocess module with shell=False instead of os.system."),
            ]
        }

        if language not in patterns:
            return errors

        language_patterns = patterns[language]
        code_lines = code.splitlines() if isinstance(code, str) else code

        for i, line in enumerate(code_lines):
            for pattern, code_id, message, category, severity, suggestion in language_patterns:
                if re.search(pattern, line):
                    errors.append(CodeError(
                        type=code_id,
                        message=message,
                        line_start=i + 1,
                        category=category,
                        severity=severity,
                        suggestion=suggestion,
                        affected_code=line.strip(),
                        
                    ))

        return errors

    def run_pylint_analysis(self, code: str) -> List[CodeError]:
        errors = []
        with tempfile.NamedTemporaryFile(delete=False, suffix=".py", mode='w', encoding='utf-8') as temp_file:
            temp_file.write(code)
            temp_file_path = temp_file.name

        try:
            result = subprocess.run(
                ["pylint", temp_file_path, "--disable=all", "--enable=E,W,C,R", "--output-format=text"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            for line in result.stdout.splitlines():
                # Пример строки: test.py:1:0: C0114: Missing module docstring (missing-module-docstring)
                match = re.match(r'^.+:(\d+):\d+:\s+([A-Z]\d+):\s+(.*?)(\s\([^)]+\))?$', line)
                if match:
                    line_number = int(match.group(1))
                    code_id = match.group(2)
                    message = match.group(3).strip()

                    # Классификация по типу ошибки
                    if code_id.startswith("E"):
                        severity = ErrorSeverity.HIGH
                        category = ErrorCategory.SYNTAX
                    elif code_id.startswith("W"):
                        severity = ErrorSeverity.MEDIUM
                        category = ErrorCategory.BEST_PRACTICE
                    else:
                        severity = ErrorSeverity.LOW
                        category = ErrorCategory.STYLE

                    errors.append(CodeError(
                        type=code_id,
                        message=message,
                        line_start=line_number,
                        category=category,
                        severity=severity,
                        suggestion="Review the pylint warning.",
                        affected_code=""
                    ))

        finally:
            os.remove(temp_file_path)

        return errors

  
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        try:
            self.current_file = file_path
            
            # Parse the file
            self.parsed_code = self.parser.parse_file(file_path)
            
            if not self.parsed_code.get("success", False):
                parsing_error = self._create_parsing_error(self.parsed_code.get("error", "Unknown parsing error"))
                return {
                    "success": False,
                    "file_path": file_path,
                    "errors": [parsing_error.to_pydantic_model()]
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
                    type="UNSUPPORTED_LANGUAGE",
                    message=f"Full error detection for {self.current_language} not implemented yet",
                    line_start=1,
                    category=ErrorCategory.INFO,
                    severity=ErrorSeverity.INFO
                ))
            
            # Common detectors that work across languages
            errors.extend(self._detect_common_issues())
            
            # Преобразуем наши объекты CodeError в Pydantic-модели
            pydantic_errors = [error.to_pydantic_model() for error in errors]
            
            # Создаем рекомендации на основе ошибок
            recommendations = []
            for error in errors:
                if error.suggestion:
                    # Создаем объект RecommendationDetail для каждой ошибки с предложением
                    recommendations.append(RecommendationDetail(
                        original_error=error.to_pydantic_model(),
                        suggested_fix=error.suggestion
                    ))
            
            # Создаем заглушку для структуры кода (в реальном коде здесь должен быть 
            # анализ структуры кода из parsed_code)
            code_structure = CodeStructureDetail(
                functions=[],  # Здесь должен быть список функций из кода
                classes=[],    # Здесь должен быть список классов из кода
                imports=[]     # Здесь должен быть список импортов из кода
            )
            
            return {
                "success": True,
                "file_path": file_path,
                "language": self.current_language,
                "code_structure": code_structure,
                "errors": pydantic_errors,
                "recommendations": recommendations,
                "error_count": len(errors),
                "error_summary": self._summarize_errors(errors)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {str(e)}")
            exception_error = self._create_exception_error(e)
            return {
                "success": False,
                "file_path": file_path,
                "errors": [exception_error.to_pydantic_model()]
            }
      
    def _create_parsing_error(self, error_message: str) -> CodeError:
        """Create a standardized error for parsing failures."""
        return CodeError(
            type="PARSE_ERROR",
            message=f"Failed to parse file: {error_message}",
            line_start=1,
            category=ErrorCategory.SYNTAX,
            severity=ErrorSeverity.CRITICAL
        )
    
    def _create_exception_error(self, exception: Exception) -> CodeError:
        """Create a standardized error for exceptions during analysis."""
        return CodeError(
            type="ANALYSIS_ERROR",
            message=f"Error during analysis: {str(exception)}",
            line_start=1,
            category=ErrorCategory.SYNTAX,
            severity=ErrorSeverity.CRITICAL
        )
    
    def _summarize_errors(self, errors: List[CodeError]) -> Dict[str, int]:

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
                type="PY_SYNTAX_ERROR",
                message=f"Python syntax error: {error_info['msg']}",
                line_start=error_info["line"],
                column_start=error_info["column"],
                category=ErrorCategory.SYNTAX,
                severity=ErrorSeverity.CRITICAL,
                affected_code=error_info["text"]
            ))
            
        return errors
    
    def _detect_python_syntax_errors(self, ast_tree: ast.AST) -> List[CodeError]:

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
                        type="PY_UNDEFINED_VAR",
                        message=f"Potentially undefined variable: {node.id}",
                        line_start=node.lineno,
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
                                type="PY_MUTABLE_DEFAULT",
                                message=f"Mutable default argument: {arg_name}",
                                line_start=node.lineno,
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
                            type="PY_HARDCODED_PATH",
                            message=f"Hardcoded file path: {node.s}",
                            line_start=node.lineno,
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
                                type="PY_HARDCODED_PATH",
                                message=f"Hardcoded file path: {node.value}",
                                line_start=node.lineno,
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
                        type="PY_BARE_EXCEPT",
                        message="Bare except clause",
                        line_start=node.lineno,
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
                        type="PY_SECURITY_RISK",
                        message=insecure_functions[func_name],
                        line_start=node.lineno,
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
                                type="PY_SQL_INJECTION",
                                message="Potential SQL injection vulnerability",
                                line_start=node.lineno,
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

        errors = []
        
        # Check for missing docstrings
        class DocstringChecker(ast.NodeVisitor):
            def visit_Module(self, node):
                if not ast.get_docstring(node):
                    errors.append(CodeError(
                        type="PY_NO_MODULE_DOCSTRING",
                        message="Missing module docstring",
                        line_start=1,
                        category=ErrorCategory.STYLE,
                        severity=ErrorSeverity.LOW,
                        suggestion="Add a module-level docstring at the beginning of the file."
                    ))
                self.generic_visit(node)
                
            def visit_ClassDef(self, node):
                if not ast.get_docstring(node):
                    errors.append(CodeError(
                        type="PY_NO_CLASS_DOCSTRING",
                        message=f"Missing docstring for class '{node.name}'",
                        line_start=node.lineno,
                        category=ErrorCategory.STYLE,
                        severity=ErrorSeverity.LOW,
                        suggestion=f"Add a docstring for class '{node.name}'."
                    ))
                self.generic_visit(node)
                
            def visit_FunctionDef(self, node):
                # Skip dunder methods (__init__ etc.) for docstring checks
                if not node.name.startswith('__') and not ast.get_docstring(node):
                    errors.append(CodeError(
                        type="PY_NO_FUNCTION_DOCSTRING",
                        message=f"Missing docstring for function '{node.name}'",
                        line_start=node.lineno,
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
                        type="PY_COMPLEX_FUNCTION",
                        message=f"Function '{node.name}' is too complex ({statement_count} statements)",
                        line_start=node.lineno,
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

        # This is a simplified implementation. In a real-world application,
        # you would use a proper JavaScript parser and linter.
        errors = []
        
        # Very basic pattern-based detections
        js_patterns = [
            (r'console\.log\(', "JS_CONSOLE_LOG", "Console log statement in production code", 
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
            for pattern, error_type, message, category, severity, suggestion in js_patterns:
                if re.search(pattern, line):
                    errors.append(CodeError(
                        type=error_type,  # Исправлено: было code=code, теперь type=error_type
                        message=message,
                        line_start=i + 1, 
                        category=category,
                        severity=severity,
                        suggestion=suggestion,
                        affected_code=line.strip()
                    ))
        
        return errors
    
    def _detect_common_issues(self) -> List[CodeError]:

        errors = []
        
        # Check for lines that are too long
        if hasattr(self.parser, 'code_lines') and self.parser.code_lines:
            for i, line in enumerate(self.parser.code_lines):
                if len(line) > 100:  # Arbitrary threshold
                    errors.append(CodeError(
                        type="COMMON_LONG_LINE", 
                        message=f"Line too long ({len(line)} characters)",
                        line_start=i + 1, 
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
                        type="COMMON_TODO_COMMENT",  # Исправлено: было COMMON_LONG_LINE
                        message=f"TODO or FIXME comment found",
                        line_start=i + 1,
                        category=ErrorCategory.INFO,
                        severity=ErrorSeverity.INFO,
                        affected_code=line.strip()
                    ))
        
        return errors
    
    def analyze_directory(self, directory_path: str) -> Dict[str, Dict[str, Any]]:

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
                print(f"  - Line {error.line_start}: {error.message} ({error.severity})")
                if error.suggestion:
                    print(f"    Suggestion: {error.suggestion}")
                print()
    finally:
        # Clean up
        os.unlink(temp_file)