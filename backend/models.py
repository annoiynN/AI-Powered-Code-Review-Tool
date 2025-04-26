from pydantic import BaseModel
from typing import List, Dict, Optional, Any, Union


class CodeAnalysisRequest(BaseModel):
    code: str
    language: str = "python"
    generate_pdf: bool = False


class ErrorDetail(BaseModel):
    type: str
    message: str
    source: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    context: Optional[str] = None


class CodeError(BaseModel):
    type: str                    
    message: str                 
    line_start: int              
    line_end: Optional[int] = None
    column_start: Optional[int] = None
    column_end: Optional[int] = None
    category: Optional[str] = None       
    severity: str                
    suggestion: Optional[str] = None     
    affected_code: Optional[str] = None       


class CodeStructureDetail(BaseModel):
    functions: List[Dict[str, Any]]
    classes: List[Dict[str, Any]]
    imports: List[str]


class RecommendationDetail(BaseModel):
    original_error: CodeError
    suggested_fix: str


class CodeAnalysisResponse(BaseModel):
    code_structure: CodeStructureDetail
    errors: List[CodeError]
    recommendations: List[RecommendationDetail]


class CodeAnalysisResponseWithPDF(BaseModel):
    analysis: CodeAnalysisResponse
    pdf_content: Optional[str] = None  # Base64 encoded PDF content