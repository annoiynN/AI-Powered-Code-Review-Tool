"""
code_parser.py - Module for parsing source code into AST (Abstract Syntax Tree)
and extracting relevant information for analysis.

This module is responsible for:
1. Parsing different programming languages into a standardized format
2. Extracting code structure information
3. Providing interfaces for other modules to access code information
"""

import ast
import os
import re
from typing import Dict, List, Any, Union, Optional, Tuple
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CodeParser:
    """Main class for parsing source code files."""
    
    SUPPORTED_LANGUAGES = {
        'python': ['.py'],
        'javascript': ['.js', '.jsx', '.ts', '.tsx'],
        'java': ['.java'],
        'csharp': ['.cs'],
        'c': ['.c', '.h'],
        'cpp': ['.cpp', '.hpp', '.cc', '.hh'],
    }
    
    def __init__(self):
        """Initialize the code parser."""
        self.current_file = None
        self.current_language = None
        self.ast_tree = None
        self.code_lines = []
        
    def detect_language(self, file_path: str) -> str:
        """
        Detect the programming language based on file extension.
        
        Args:
            file_path: Path to the source code file
            
        Returns:
            String representing the detected language
        """
        _, extension = os.path.splitext(file_path)
        
        for language, extensions in self.SUPPORTED_LANGUAGES.items():
            if extension in extensions:
                return language
                
        return "unknown"
    
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a source code file and return its structured representation.
        
        Args:
            file_path: Path to the source code file
            
        Returns:
            Dictionary containing parsed code information
        """
        try:
            self.current_file = file_path
            self.current_language = self.detect_language(file_path)
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                self.code_lines = content.split('\n')
            
            if self.current_language == "unknown":
                logger.warning(f"Unsupported file type: {file_path}")
                return {"success": False, "error": "Unsupported file type"}
                
            parser_method = getattr(self, f"_parse_{self.current_language}", None)
            
            if parser_method is None:
                logger.warning(f"Parser not implemented for {self.current_language}")
                return {"success": False, "error": f"Parser not implemented for {self.current_language}"}
                
            result = parser_method(content)
            result["file_path"] = file_path
            result["language"] = self.current_language
            result["success"] = True
            
            return result
            
        except Exception as e:
            logger.error(f"Error parsing file {file_path}: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _parse_python(self, content: str) -> Dict[str, Any]:
        """
        Parse Python code into structured format.
        
        Args:
            content: String containing Python code
            
        Returns:
            Dictionary with parsed Python code information
        """
        try:
            self.ast_tree = ast.parse(content)
            
            # Extract imports
            imports = []
            for node in ast.walk(self.ast_tree):
                if isinstance(node, ast.Import):
                    for name in node.names:
                        imports.append({"module": name.name, "alias": name.asname})
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for name in node.names:
                        imports.append({"module": f"{module}.{name.name}", "alias": name.asname})
            
            # Extract functions and classes
            functions = []
            classes = []
            
            for node in self.ast_tree.body:
                if isinstance(node, ast.FunctionDef):
                    functions.append(self._extract_python_function(node))
                elif isinstance(node, ast.ClassDef):
                    classes.append(self._extract_python_class(node))
            
            return {
                "imports": imports,
                "functions": functions,
                "classes": classes,
                "ast": self.ast_tree
            }
            
        except SyntaxError as e:
            logger.error(f"Python syntax error: {str(e)}")
            return {
                "imports": [],
                "functions": [],
                "classes": [],
                "syntax_error": {
                    "line": e.lineno,
                    "column": e.offset,
                    "text": e.text,
                    "msg": str(e)
                }
            }
    
    def _extract_python_function(self, node: ast.FunctionDef) -> Dict[str, Any]:
        """Extract details about a Python function from its AST node."""
        arguments = []
        defaults = [None] * (len(node.args.args) - len(node.args.defaults)) + node.args.defaults
        
        for i, arg in enumerate(node.args.args):
            arg_info = {
                "name": arg.arg,
                "annotation": ast.unparse(arg.annotation) if arg.annotation else None,
                "default": ast.unparse(defaults[i]) if defaults[i] else None
            }
            arguments.append(arg_info)
            
        docstring = ast.get_docstring(node)
        
        return {
            "name": node.name,
            "lineno": node.lineno,
            "end_lineno": getattr(node, "end_lineno", None),
            "arguments": arguments,
            "returns": ast.unparse(node.returns) if node.returns else None,
            "docstring": docstring,
            "decorators": [ast.unparse(decorator) for decorator in node.decorator_list]
        }
    
    def _extract_python_class(self, node: ast.ClassDef) -> Dict[str, Any]:
        """Extract details about a Python class from its AST node."""
        methods = []
        attributes = []
        
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                methods.append(self._extract_python_function(item))
            elif isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name):
                        attributes.append({
                            "name": target.id,
                            "value": ast.unparse(item.value),
                            "lineno": item.lineno
                        })
                        
        docstring = ast.get_docstring(node)
        
        return {
            "name": node.name,
            "lineno": node.lineno,
            "end_lineno": getattr(node, "end_lineno", None),
            "bases": [ast.unparse(base) for base in node.bases],
            "methods": methods,
            "attributes": attributes,
            "docstring": docstring,
            "decorators": [ast.unparse(decorator) for decorator in node.decorator_list]
        }
    
    def _parse_javascript(self, content: str) -> Dict[str, Any]:
        """
        Basic parsing for JavaScript (placeholder - would require a JS parser like esprima)
        
        In a production system, this would use a proper JavaScript parser
        """
        # Simple regex-based extraction for demonstration
        functions = []
        classes = []
        imports = []
        
        # Extract imports (very basic)
        import_pattern = re.compile(r'(import|require)\s+[{]?([^;]+)[}]?\s+from\s+[\'"]([^\'"]+)[\'"]')
        for match in import_pattern.finditer(content):
            imports.append({
                "module": match.group(3),
                "elements": match.group(2).strip()
            })
        
        # Extract function declarations (simplified)
        function_pattern = re.compile(r'function\s+(\w+)\s*\(([^)]*)\)')
        for match in function_pattern.finditer(content):
            functions.append({
                "name": match.group(1),
                "arguments": [arg.strip() for arg in match.group(2).split(',') if arg.strip()],
                "lineno": content[:match.start()].count('\n') + 1
            })
        
        # Extract class declarations (simplified)
        class_pattern = re.compile(r'class\s+(\w+)(?:\s+extends\s+(\w+))?\s*{')
        for match in class_pattern.finditer(content):
            classes.append({
                "name": match.group(1),
                "extends": match.group(2),
                "lineno": content[:match.start()].count('\n') + 1
            })
        
        return {
            "imports": imports,
            "functions": functions,
            "classes": classes
        }
    
    # Placeholder methods for other languages
    def _parse_java(self, content: str) -> Dict[str, Any]:
        """Placeholder for Java parsing"""
        return {"message": "Java parsing not fully implemented yet xd"}
    
    def _parse_csharp(self, content: str) -> Dict[str, Any]:
        """Placeholder for C# parsing"""
        return {"message": "C# parsing not fully implemented yet xd"}
    
    def _parse_c(self, content: str) -> Dict[str, Any]:
        """Placeholder for C parsing"""
        return {"message": "C parsing not fully implemented yet xd"}
    
    def _parse_cpp(self, content: str) -> Dict[str, Any]:
        """Placeholder for C++ parsing"""
        return {"message": "C++ parsing not fully implemented yet xd"}
    
    def get_line_range(self, start_line: int, end_line: int) -> List[str]:
        """
        Get specific lines of code from the parsed file
        
        Args:
            start_line: Starting line number (1-based indexing)
            end_line: Ending line number (inclusive)
            
        Returns:
            List of code lines
        """
        if not self.code_lines:
            return []
            
        # Adjust for 0-based indexing
        start_idx = max(0, start_line - 1)
        end_idx = min(len(self.code_lines), end_line)
        
        return self.code_lines[start_idx:end_idx]
    
    def get_function_body(self, function_name: str) -> Union[List[str], None]:
        """
        Extract the body of a specific function by name
        
        Args:
            function_name: Name of the function to extract
            
        Returns:
            List of code lines that make up the function body or None if not found
        """
        if self.current_language != "python" or not self.ast_tree:
            return None
            
        for node in ast.walk(self.ast_tree):
            if isinstance(node, ast.FunctionDef) and node.name == function_name:
                start_line = node.lineno
                end_line = getattr(node, "end_lineno", start_line + 1)
                return self.get_line_range(start_line, end_line)
                
        return None

    @classmethod
    def parse_python_code(cls, code: str) -> Dict[str, Any]:

        
        instance = cls()
        return instance._parse_python(code)



def parse_directory(directory_path: str) -> Dict[str, Dict[str, Any]]:

    parser = CodeParser()
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
                results[file_path] = parser.parse_file(file_path)
                
    return results


if __name__ == "__main__":
    # Example usage
    parser = CodeParser()
    sample_code = """
def hello_world(name: str = "World") -> str:
    \"\"\"Return a greeting message.\"\"\"
    return f"Hello, {name}!"
    
class Example:
    \"\"\"Example class for demonstration.\"\"\"
    def __init__(self, value=0):
        self.value = value
        
    def increment(self, amount=1):
        self.value += amount
        return self.value
"""
    
    # Create a temporary file for testing
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.py', mode='w+', delete=False) as f:
        f.write(sample_code)
        temp_file = f.name
    
    try:
        # Parse the file and print results
        result = parser.parse_file(temp_file)
        print("Parsing result:", result)
        
        # Example of extracting a function body
        if result["success"]:
            function_body = parser.get_function_body("hello_world")
            print("\nFunction body for 'hello_world':")
            print("\n".join(function_body))
    finally:
        # Clean up
        os.unlink(temp_file)