from pydantic import BaseModel
from typing import List, Dict, Optional, Any, Union

class CodeAnalysisRequest(BaseModel):
    code: str
    language: str = "python"
    generate_pdf: bool = False

class ErrorDetail(BaseModel):
    type: str
    message: str
    line: int
    severity: str

class CodeStructureDetail(BaseModel):
    functions: List[Dict[str, Any]]
    classes: List[Dict[str, Any]]
    imports: List[str]

class RecommendationDetail(BaseModel):
    original_error: ErrorDetail
    suggested_fix: str

class CodeAnalysisResponse(BaseModel):
    code_structure: CodeStructureDetail
    errors: List[ErrorDetail]
    recommendations: List[RecommendationDetail]

class CodeAnalysisResponseWithPDF(BaseModel):
    analysis: CodeAnalysisResponse
    pdf_content: Optional[str] = None  # Base64 encoded PDF content