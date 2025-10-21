"""
PDF Processing for CONDUIT

Extracts text from PDF documents using PyMuPDF4LLM for optimal LLM processing.
Based on proven extraction patterns from ai-powered-assurance-workflows.
"""

import pymupdf4llm
from pathlib import Path
from typing import Optional, Tuple, Union
import logging

logger = logging.getLogger(__name__)


def pdf_to_text(
    pdf_path: Union[str, Path],
    page_range: Optional[Tuple[int, int]] = None
) -> str:
    """
    Extract markdown-formatted text from PDF using PyMuPDF4LLM.

    This function uses pymupdf4llm.to_markdown() which preserves:
    - Document structure and formatting
    - Tables and structured content
    - Headings and sections

    Args:
        pdf_path: Path to PDF file (SOC 2 report, compliance doc, etc.)
        page_range: Optional (start, end) page numbers to extract

    Returns:
        Markdown-formatted text ready for Claude API

    Raises:
        FileNotFoundError: If PDF doesn't exist
        ValueError: If file is not a PDF
        RuntimeError: If extraction fails

    Examples:
        >>> text = pdf_to_text("soc2_report.pdf")
        >>> print(f"Extracted {len(text)} characters")

        >>> # Extract specific pages
        >>> text = pdf_to_text("report.pdf", page_range=(10, 20))
    """
    pdf_path = Path(pdf_path)

    # Validate file exists
    if not pdf_path.exists():
        raise FileNotFoundError(f"PDF not found: {pdf_path}")

    # Validate file extension
    if pdf_path.suffix.lower() != '.pdf':
        raise ValueError(f"Not a PDF file: {pdf_path.suffix}")

    try:
        logger.info(f"Extracting text from PDF: {pdf_path.name}")

        # Extract using pymupdf4llm (proven pattern)
        # This returns markdown-formatted text optimized for LLMs
        if page_range:
            start_page, end_page = page_range
            markdown_text = pymupdf4llm.to_markdown(
                str(pdf_path),
                pages=list(range(start_page, end_page + 1))
            )
        else:
            markdown_text = pymupdf4llm.to_markdown(str(pdf_path))

        logger.info(f"Successfully extracted {len(markdown_text)} characters")
        return markdown_text

    except Exception as e:
        logger.error(f"PDF extraction failed: {str(e)}")
        raise RuntimeError(f"Failed to extract text from {pdf_path.name}: {str(e)}")


def get_pdf_metadata(pdf_path: Union[str, Path]) -> dict:
    """
    Extract basic metadata from PDF.

    Args:
        pdf_path: Path to PDF file

    Returns:
        Dictionary with file name, size, and page count

    Examples:
        >>> metadata = get_pdf_metadata("soc2_report.pdf")
        >>> print(f"Pages: {metadata['page_count']}")
    """
    import pymupdf

    pdf_path = Path(pdf_path)

    if not pdf_path.exists():
        raise FileNotFoundError(f"PDF not found: {pdf_path}")

    try:
        doc = pymupdf.open(str(pdf_path))
        metadata = {
            'file_name': pdf_path.name,
            'file_size_mb': pdf_path.stat().st_size / (1024 * 1024),
            'page_count': len(doc)
        }
        doc.close()

        return metadata

    except Exception as e:
        logger.error(f"Failed to get PDF metadata: {str(e)}")
        return {
            'file_name': pdf_path.name,
            'file_size_mb': pdf_path.stat().st_size / (1024 * 1024),
            'page_count': None
        }
