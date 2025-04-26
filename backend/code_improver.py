"""
code_improver.py - Module for suggesting improvements to source code.

This module is responsible for:
1. Suggesting refactorings to improve code structure
2. Recommending performance optimizations
3. Proposing style improvements
4. Providing automatic fixes for detected issues
5. Generating improved code alternatives
"""

import ast
import re
import logging
import difflib
from typing import Dict, List, Any, Union, Optional, Tuple
import os

# Import related modules
from backend.code_parser import CodeParser
from backend.error_detector import ErrorDetector, CodeError, ErrorCategory, ErrorSeverity

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ImprovementCategory:
    """Constants for improvement categories."""
    REFACTORING = "refactoring"
    PERFORMANCE = "performance"
    STYLE = "style"
    SECURITY = "security"
    READABILITY = "readability"
    MAINTAINABILITY = "maintainability"

class ImprovementSuggestion:
    """Class representing a suggested improvement to the code."""
    
    def __init__(
        self,
        code: str,
        message: str,
        line_start: int,
        line_end: Optional[int] = None,
        category: str = ImprovementCategory.READABILITY,
        original_code: Optional[str] = None,
        improved_code: Optional[str] = None,
        explanation: Optional[str] = None
    ):
        """
        Initialize an improvement suggestion.
        
        Args:
            code: Suggestion identifier code
            message: Human-readable suggestion message
            line_start: Line number where the improvement starts (1-based)
            line_end: Line number where the improvement ends (optional)
            category: Improvement category
            original_code: The original code snippet
            improved_code: The suggested improved code
            explanation: Explanation of why the improvement is beneficial
        """
        self.code = code
        self.message = message
        self.line_start = line_start
        self.line_end = line_end or line_start
        self.category = category
        self.original_code = original_code
        self.improved_code = improved_code
        self.explanation = explanation
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the suggestion to a dictionary representation."""
        return {
            "code": self.code,
            "message": self.message,
            "location": {
                "line_start": self.line_start,
                "line_end": self.line_end
            },
            "category": self.category,
            "original_code": self.original_code,
            "improved_code": self.improved_code,
            "explanation": self.explanation
        }
    
    def format_diff(self) -> str:
        """Generate a unified diff between original and improved code."""
        if not self.original_code or not self.improved_code:
            return ""
            
        original_lines = self.original_code.splitlines(True)
        improved_lines = self.improved_code.splitlines(True)
        
        diff = difflib.unified_diff(
            original_lines,
            improved_lines,
            fromfile="Original",
            tofile="Improved",
            n=3  # Context lines
        )
        
        return "".join(diff)

class CodeImprover:
    """Main class for suggesting code improvements."""
    #fix 
    def generate_improvements(self, code, language=None, options=None):
      if language:
          self.current_language = language
  
      return self.improve_code(code)
    
    def __init__(self):
        """Initialize the code improver."""
        self.parser = CodeParser()
        self.error_detector = ErrorDetector()
        self.current_file = None
        self.current_language = None
        self.parsed_code = None
        self.code_lines = []
        self.error_analysis = None
        
    def improve_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze a source code file and suggest improvements.
        
        Args:
            file_path: Path to the source code file
            
        Returns:
            Dictionary containing suggested improvements
        """
        try:
            self.current_file = file_path
            
            # Determine language from file extension
            self.current_language = os.path.splitext(file_path)[1].lstrip('.')
            
            # Parse the code
            with open(file_path, 'r', encoding='utf-8') as f:
                code_content = f.read()
            
            return self.improve_code(code_content)
            
        except Exception as e:
            logger.error(f"Error improving file {file_path}: {str(e)}")
            return {"error": str(e), "suggestions": []}
    
    def improve_code(self, code_content: str) -> Dict[str, Any]:
        """
        Analyze code content and suggest improvements.
        
        Args:
            code_content: Source code as a string
            
        Returns:
            Dictionary containing suggested improvements
        """
        try:
            # Parse the code
            self.parsed_code = self.parser.parse_code(code_content)
            self.code_lines = code_content.splitlines()
            
            # Get errors from the error detector
            self.error_analysis = self.error_detector.analyze_code(code_content)
            
            # Generate suggestions
            suggestions = []
            suggestions.extend(self._suggest_from_errors())
            suggestions.extend(self._suggest_style_improvements())
            suggestions.extend(self._suggest_refactorings())
            suggestions.extend(self._suggest_performance_improvements())
            
            return {
                "file": self.current_file,
                "language": self.current_language,
                "total_lines": len(self.code_lines),
                "suggestions": [s.to_dict() for s in suggestions]
            }
            
        except Exception as e:
            logger.error(f"Error improving code: {str(e)}")
            return {"error": str(e), "suggestions": []}
    
    def _suggest_from_errors(self) -> List[ImprovementSuggestion]:
        """Generate improvement suggestions based on detected errors."""
        suggestions = []
        
        if not self.error_analysis or "errors" not in self.error_analysis:
            return suggestions
            
        for error in self.error_analysis["errors"]:
            # Skip errors that don't have a clear fix
            if error.severity == ErrorSeverity.CRITICAL:
                continue
                
            line_start = error.line_start
            line_end = error.line_end or error.line_start
            
            # Get the code snippet
            original_code = "\n".join(self.code_lines[line_start-1:line_end])
            improved_code = None
            
            # Generate fixes based on error category
            if error.category == ErrorCategory.SYNTAX:
                improved_code = self._fix_syntax_error(original_code, error)
            elif error.category == ErrorCategory.SEMANTIC:
                improved_code = self._fix_semantic_error(original_code, error)
            elif error.category == ErrorCategory.STYLE:
                improved_code = self._fix_style_error(original_code, error)
                
            if improved_code:
                suggestions.append(ImprovementSuggestion(
                    code=f"FIX_{error.code}",
                    message=f"Fix for: {error.message}",
                    line_start=line_start,
                    line_end=line_end,
                    category=ImprovementCategory.REFACTORING,
                    original_code=original_code,
                    improved_code=improved_code,
                    explanation=f"This change fixes the detected issue: {error.message}"
                ))
                
        return suggestions
    
    def _suggest_style_improvements(self) -> List[ImprovementSuggestion]:
        """Suggest style improvements for the code."""
        suggestions = []
        
        # Check for line length
        for i, line in enumerate(self.code_lines):
            if len(line.rstrip()) > 100:  # PEP 8 recommends 79, but many projects use 100
                suggestions.append(ImprovementSuggestion(
                    code="STYLE_LINE_LENGTH",
                    message="Consider breaking long line into multiple lines",
                    line_start=i + 1,
                    category=ImprovementCategory.STYLE,
                    original_code=line,
                    improved_code=self._break_long_line(line),
                    explanation="PEP 8 recommends keeping lines under 79 characters for improved readability."
                ))
        
        # Check for variable naming consistency
        if self.current_language == 'py':
            suggestions.extend(self._check_python_naming())
            
        return suggestions
    
    def _suggest_refactorings(self) -> List[ImprovementSuggestion]:
        """Suggest code refactorings."""
        suggestions = []
        
        # Check for repeated code blocks
        suggestions.extend(self._detect_repeated_code())
        
        # Check for overly complex functions
        suggestions.extend(self._detect_complex_functions())
        
        # Check for long parameter lists
        suggestions.extend(self._detect_long_parameter_lists())
        
        return suggestions
    
    def _suggest_performance_improvements(self) -> List[ImprovementSuggestion]:
        """Suggest performance improvements."""
        suggestions = []
        
        # Check for inefficient operations
        if self.current_language == 'py':
            suggestions.extend(self._check_python_performance())
            
        return suggestions
    
    def _fix_syntax_error(self, code: str, error: CodeError) -> Optional[str]:
        """Generate a fix for a syntax error."""
        # Simple fixes for common Python syntax errors
        if "unexpected EOF" in error.message or "expected an indented block" in error.message:
            # Add missing colon or fix indentation
            return code + ":"
        elif "invalid syntax" in error.message and ":" in code:
            # Check for missing colons at the end of control flow statements
            if re.search(r'(if|for|while|def|class)\s+.*[^:]$', code):
                return re.sub(r'(if|for|while|def|class\s+.*[^:])$', r'\1:', code)
                
        return None
    
    def _fix_semantic_error(self, code: str, error: CodeError) -> Optional[str]:
        """Generate a fix for a semantic error."""
        # Handle common semantic errors
        if "undefined variable" in error.message.lower():
            # Extract the variable name
            match = re.search(r"undefined variable '(\w+)'", error.message)
            if match:
                var_name = match.group(1)
                return f"{var_name} = None  # TODO: Initialize this variable properly\n{code}"
                
        return None
    
    def _fix_style_error(self, code: str, error: CodeError) -> Optional[str]:
        """Generate a fix for a style error."""
        # Handle common style errors
        if "whitespace" in error.message.lower():
            # Fix whitespace around operators
            improved = re.sub(r'(\w+)([+\-*/=])(\w+)', r'\1 \2 \3', code)
            if improved != code:
                return improved
                
        return None
    
    def _break_long_line(self, line: str) -> str:
        """Break a long line of code into multiple lines."""
        # Simple approach for demonstration - real implementation would be more sophisticated
        if "(" in line and ")" in line:
            # Split parameters in function calls or definitions
            return line.replace(", ", ",\n    ")
        elif "+" in line:
            # Break string concatenations or additions
            return line.replace(" + ", " +\n    ")
            
        return line
    
    def _check_python_naming(self) -> List[ImprovementSuggestion]:
        """Check Python code for naming convention issues."""
        suggestions = []
        
        # Use ast to parse Python code and check naming conventions
        try:
            tree = ast.parse("\n".join(self.code_lines))
            
            class NamingVisitor(ast.NodeVisitor):
                def __init__(self):
                    self.naming_issues = []
                
                def visit_ClassDef(self, node):
                    # Classes should use CamelCase
                    if not re.match(r'^[A-Z][a-zA-Z0-9]*$', node.name):
                        self.naming_issues.append((
                            node.lineno,
                            node.name,
                            "class",
                            "CamelCase"
                        ))
                    self.generic_visit(node)
                
                def visit_FunctionDef(self, node):
                    # Functions should use snake_case
                    if not re.match(r'^[a-z][a-z0-9_]*$', node.name) and not node.name.startswith('__'):
                        self.naming_issues.append((
                            node.lineno,
                            node.name,
                            "function",
                            "snake_case"
                        ))
                    self.generic_visit(node)
                
                def visit_Name(self, node):
                    # Check for constants in all caps
                    if isinstance(node.ctx, ast.Store) and re.match(r'^[A-Z][A-Z0-9_]*$', node.id):
                        # This might be a constant, but we need more context to be sure
                        pass
                    self.generic_visit(node)
            
            visitor = NamingVisitor()
            visitor.visit(tree)
            
            for lineno, name, entity_type, convention in visitor.naming_issues:
                suggestions.append(ImprovementSuggestion(
                    code=f"NAMING_{entity_type.upper()}",
                    message=f"{entity_type} name '{name}' does not follow {convention} convention",
                    line_start=lineno,
                    category=ImprovementCategory.STYLE,
                    explanation=f"Python {entity_type} names should follow {convention} convention for better readability and consistency."
                ))
                
        except SyntaxError:
            # If there are syntax errors, ast.parse will fail
            pass
            
        return suggestions
    
    def _detect_repeated_code(self) -> List[ImprovementSuggestion]:
        """Detect repeated code blocks that could be refactored."""
        suggestions = []
        
        # Simple detection of repeated lines (3+ lines)
        line_blocks = {}
        block_size = 3
        
        for i in range(len(self.code_lines) - block_size + 1):
            block = "\n".join(self.code_lines[i:i+block_size])
            if block.strip():  # Skip empty blocks
                if block in line_blocks:
                    line_blocks[block].append(i+1)
                else:
                    line_blocks[block] = [i+1]
        
        for block, lines in line_blocks.items():
            if len(lines) > 1:
                suggestions.append(ImprovementSuggestion(
                    code="REFACTOR_REPEATED_CODE",
                    message=f"Repeated code block found at lines {', '.join(map(str, lines))}",
                    line_start=lines[0],
                    line_end=lines[0] + block_size - 1,
                    category=ImprovementCategory.REFACTORING,
                    original_code=block,
                    explanation="Consider extracting this repeated code into a function to improve maintainability."
                ))
                
        return suggestions
    
    def _detect_complex_functions(self) -> List[ImprovementSuggestion]:
        """Detect overly complex functions."""
        suggestions = []
        
        if self.current_language == 'py':
            try:
                tree = ast.parse("\n".join(self.code_lines))
                
                class ComplexityVisitor(ast.NodeVisitor):
                    def __init__(self):
                        self.complex_functions = []
                    
                    def visit_FunctionDef(self, node):
                        # Simple complexity metric: count branches and loops
                        branches = 0
                        
                        class BranchCounter(ast.NodeVisitor):
                            def visit_If(self, node):
                                nonlocal branches
                                branches += 1
                                self.generic_visit(node)
                            
                            def visit_For(self, node):
                                nonlocal branches
                                branches += 1
                                self.generic_visit(node)
                            
                            def visit_While(self, node):
                                nonlocal branches
                                branches += 1
                                self.generic_visit(node)
                                
                        BranchCounter().visit(node)
                        
                        if branches > 5:  # Arbitrary threshold
                            self.complex_functions.append((
                                node.name,
                                node.lineno,
                                branches
                            ))
                        
                        self.generic_visit(node)
                
                visitor = ComplexityVisitor()
                visitor.visit(tree)
                
                for func_name, lineno, complexity in visitor.complex_functions:
                    suggestions.append(ImprovementSuggestion(
                        code="REFACTOR_COMPLEX_FUNCTION",
                        message=f"Function '{func_name}' has high complexity ({complexity} branches)",
                        line_start=lineno,
                        category=ImprovementCategory.REFACTORING,
                        explanation=f"Consider breaking this function into smaller, more focused functions to improve readability and maintainability."
                    ))
                    
            except SyntaxError:
                pass
                
        return suggestions
    
    def _detect_long_parameter_lists(self) -> List[ImprovementSuggestion]:
        """Detect functions with too many parameters."""
        suggestions = []
        
        if self.current_language == 'py':
            try:
                tree = ast.parse("\n".join(self.code_lines))
                
                class ParamCountVisitor(ast.NodeVisitor):
                    def __init__(self):
                        self.long_param_functions = []
                    
                    def visit_FunctionDef(self, node):
                        param_count = len(node.args.args)
                        if param_count > 5:  # Common threshold
                            self.long_param_functions.append((
                                node.name,
                                node.lineno,
                                param_count
                            ))
                        self.generic_visit(node)
                
                visitor = ParamCountVisitor()
                visitor.visit(tree)
                
                for func_name, lineno, param_count in visitor.long_param_functions:
                    suggestions.append(ImprovementSuggestion(
                        code="REFACTOR_LONG_PARAMETER_LIST",
                        message=f"Function '{func_name}' has {param_count} parameters",
                        line_start=lineno,
                        category=ImprovementCategory.REFACTORING,
                        explanation="Functions with many parameters are harder to call and maintain. Consider using a configuration object or breaking the function into smaller functions."
                    ))
                    
            except SyntaxError:
                pass
                
        return suggestions
    
    def _check_python_performance(self) -> List[ImprovementSuggestion]:
        """Check for performance issues in Python code."""
        suggestions = []
        
        try:
            tree = ast.parse("\n".join(self.code_lines))
            
            class PerformanceVisitor(ast.NodeVisitor):
                def __init__(self):
                    self.performance_issues = []
                
                def visit_For(self, node):
                    # Check for repeated list/dict operations in loops
                    if isinstance(node.iter, ast.Call) and isinstance(node.iter.func, ast.Name):
                        if node.iter.func.id == 'range' and len(node.iter.args) == 1:
                            # Check for potential range(len(list)) pattern
                            if isinstance(node.iter.args[0], ast.Call) and isinstance(node.iter.args[0].func, ast.Name):
                                if node.iter.args[0].func.id == 'len':
                                    self.performance_issues.append((
                                        node.lineno,
                                        "range_len",
                                        "Consider using 'for item in items' instead of 'for i in range(len(items))'"
                                    ))
                    
                    self.generic_visit(node)
                
                def visit_ListComp(self, node):
                    # Check for list comprehensions that could be generator expressions
                    if isinstance(node.parent, ast.Call) and isinstance(node.parent.func, ast.Name):
                        if node.parent.func.id in ('sum', 'min', 'max', 'any', 'all'):
                            self.performance_issues.append((
                                node.lineno,
                                "use_generator_expr",
                                f"Use generator expression instead of list comprehension with {node.parent.func.id}()"
                            ))
                    self.generic_visit(node)
            
            # Add parent references to the AST
            for node in ast.walk(tree):
                for child in ast.iter_child_nodes(node):
                    child.parent = node
            
            visitor = PerformanceVisitor()
            visitor.visit(tree)
            
            for lineno, issue_type, message in visitor.performance_issues:
                suggestions.append(ImprovementSuggestion(
                    code=f"PERF_{issue_type.upper()}",
                    message=message,
                    line_start=lineno,
                    category=ImprovementCategory.PERFORMANCE,
                    explanation="This change can improve performance by avoiding unnecessary operations."
                ))
                
        except (SyntaxError, AttributeError):
            pass
            
        return suggestions