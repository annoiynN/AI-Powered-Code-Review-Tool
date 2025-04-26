from fastapi import FastAPI, UploadFile, File, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import base64
import uvicorn
from io import BytesIO
import sys
import os


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from backend.models import CodeAnalysisRequest, CodeAnalysisResponse, CodeAnalysisResponseWithPDF
from backend.services import CodeReviewService

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
    """without PDF"""
    try:
        print(f"Получен запрос на анализ кода: {len(request.code)} символов")
        result = code_review_service.review_python_code(request)
        print("Анализ завершен успешно")
        return result
    except Exception as e:
        print(f"Ошибка при анализе: {str(e)}")
        import traceback
        print(traceback.format_exc())
        raise HTTPException(status_code=400, detail=f"Ошибка анализа кода: {str(e)}")
    
@app.post("/analyze_with_pdf", response_model=CodeAnalysisResponseWithPDF)
async def analyze_code_with_pdf(request: CodeAnalysisRequest):
    """Анализ кода с опциональным PDF отчетом"""
    return code_review_service.review_with_pdf(request)

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.post("/get_pdf_report")
async def get_pdf_report(request: CodeAnalysisRequest):
    """Прямое получение PDF-отчета"""
    analysis_result = code_review_service.review_python_code(request)
    pdf_buffer = BytesIO()
    
    from backend.report_generator import PDFReportGenerator
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

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8026)