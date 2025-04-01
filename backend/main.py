from fastapi import FastAPI, UploadFile, File, Response
from fastapi.middleware.cors import CORSMiddleware
import base64
from io import BytesIO

from .models import CodeAnalysisRequest, CodeAnalysisResponse, CodeAnalysisResponseWithPDF
from .services import CodeReviewService

app = FastAPI(title="AI Code Reviewer")

# CORS настройки
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

code_review_service = CodeReviewService()

@app.post("/analyze", response_model=CodeAnalysisResponse)
async def analyze_code(request: CodeAnalysisRequest):
    """Анализ кода без PDF отчета"""
    return code_review_service.review_python_code(request)

@app.post("/analyze_with_pdf", response_model=CodeAnalysisResponseWithPDF)
async def analyze_code_with_pdf(request: CodeAnalysisRequest):
    """Анализ кода с опциональным PDF отчетом"""
    return code_review_service.review_with_pdf(request)

@app.post("/get_pdf_report")
async def get_pdf_report(request: CodeAnalysisRequest):
    """Прямое получение PDF-отчета"""
    analysis_result = code_review_service.review_python_code(request)
    pdf_buffer = BytesIO()
    
    from .report_generator import PDFReportGenerator
    pdf_buffer = PDFReportGenerator.generate_report(analysis_result, request.code)
    
    return Response(
        content=pdf_buffer.getvalue(),
        media_type="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=code_analysis_report.pdf"
        }
    )

@app.post("/upload")
async def upload_code_file(file: UploadFile = File(...), generate_pdf: bool = False):
    """Загрузка и анализ файла с кодом"""
    code_text = await file.read()
    request = CodeAnalysisRequest(
        code=code_text.decode('utf-8'),
        generate_pdf=generate_pdf
    )
    
    if generate_pdf:
        return code_review_service.review_with_pdf(request)
    else:
        return code_review_service.review_python_code(request)