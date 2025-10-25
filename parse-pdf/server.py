import asyncio
import io
import json
import logging
import os
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import aiofiles
import aiohttp
import PyPDF2
import pdfplumber
import pymupdf
import requests
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = FastMCP("PDF Parser MCP Server")

class PDFParseRequest(BaseModel):
    """Request for parsing PDF file."""
    url: str = Field(..., description="PDF file URL")
    output_format: str = Field(default="text", description="Output format: text, json")
    json_schema: Optional[Dict[str, Any]] = Field(default=None, description="JSON schema for data structuring")
    cache_enabled: bool = Field(default=True, description="Use caching")

class PDFParseResult(BaseModel):
    """Result of PDF file parsing."""
    success: bool
    text_content: Optional[str] = None
    json_content: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    processing_time: float = 0.0

class TextToJsonRequest(BaseModel):
    """Request for converting text to JSON."""
    text: str = Field(..., description="Text to convert")
    json_schema: Dict[str, Any] = Field(..., description="JSON schema for structuring")
    instructions: Optional[str] = Field(default=None, description="Additional instructions for LLM")

class TextToJsonResult(BaseModel):
    """Result of text to JSON conversion."""
    success: bool
    json_content: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

parse_cache: Dict[str, PDFParseResult] = {}

def get_cache_key(url: str, output_format: str) -> str:
    """Generates cache key for URL and format."""
    return f"{url}:{output_format}"

def is_github_url(url: str) -> bool:
    """Checks if URL is a GitHub link."""
    parsed = urlparse(url)
    return parsed.netloc in ['github.com', 'raw.githubusercontent.com']

def convert_github_url_to_raw(url: str) -> str:
    """Converts GitHub URL to raw.githubusercontent.com URL."""
    if 'raw.githubusercontent.com' in url:
        return url
    
    if 'github.com' in url:
        url = url.replace('/blob/', '/')
        url = url.replace('github.com', 'raw.githubusercontent.com')
    
    return url

async def download_pdf_async(url: str) -> bytes:
    """Downloads PDF file by URL asynchronously."""
    logger.info(f"Downloading PDF file: {url}")
    
    if is_github_url(url):
        url = convert_github_url_to_raw(url)
        logger.info(f"Converted URL: {url}")
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status != 200:
                raise Exception(f"File download error: HTTP {response.status}")
            
            content_type = response.headers.get('content-type', '')
            if 'pdf' not in content_type.lower():
                logger.warning(f"Suspicious content-type: {content_type}")
            
            return await response.read()

def download_pdf(url: str) -> bytes:
    """Downloads PDF file by URL synchronously."""
    logger.info(f"Downloading PDF file: {url}")
    
    if is_github_url(url):
        url = convert_github_url_to_raw(url)
        logger.info(f"Converted URL: {url}")
    
    response = requests.get(url, timeout=120)
    if response.status_code != 200:
        raise Exception(f"File download error: HTTP {response.status_code}")
    
    content_type = response.headers.get('content-type', '')
    if 'pdf' not in content_type.lower():
        logger.warning(f"Suspicious content-type: {content_type}")
    
    return response.content

def parse_pdf_with_pypdf2(pdf_bytes: bytes) -> str:
    """PDF parsing using PyPDF2."""
    text = ""
    try:
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(pdf_bytes))
        for page in pdf_reader.pages:
            text += page.extract_text() + "\n"
    except Exception as e:
        logger.warning(f"PyPDF2 error: {e}")
    return text

def parse_pdf_with_pdfplumber(pdf_bytes: bytes) -> str:
    """PDF parsing using pdfplumber."""
    text = ""
    try:
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
    except Exception as e:
        logger.warning(f"pdfplumber error: {e}")
    return text

def parse_pdf_with_pymupdf(pdf_bytes: bytes) -> str:
    """PDF parsing using PyMuPDF."""
    text = ""
    try:
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
        for page_num in range(doc.page_count):
            page = doc[page_num]
            text += page.get_text() + "\n"
        doc.close()
    except Exception as e:
        logger.warning(f"PyMuPDF error: {e}")
    return text

def parse_pdf_text(pdf_bytes: bytes) -> str:
    """PDF text parsing using multiple libraries."""
    logger.info("Starting PDF parsing...")
    
    methods = [
        ("PyMuPDF", parse_pdf_with_pymupdf),
        ("pdfplumber", parse_pdf_with_pdfplumber),
        ("PyPDF2", parse_pdf_with_pypdf2),
    ]
    
    best_text = ""
    best_method = ""
    
    for method_name, method_func in methods:
        try:
            text = method_func(pdf_bytes)
            if len(text.strip()) > len(best_text.strip()):
                best_text = text
                best_method = method_name
                logger.info(f"{method_name}: extracted {len(text)} characters")
        except Exception as e:
            logger.warning(f"{method_name} failed: {e}")
    
    logger.info(f"Best result: {best_method} - {len(best_text)} characters")
    return best_text.strip()

def convert_text_to_json_with_schema(text: str, json_schema: Dict[str, Any], instructions: Optional[str] = None) -> Dict[str, Any]:
    """Converts text to JSON according to the given schema."""
    result = {}
    
    if "vulnerabilities" in json_schema:
        vulnerabilities = []
        lines = text.split('\n')
        
        current_vuln = {}
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            if any(keyword in line.lower() for keyword in ['vulnerability', 'issue', 'finding', 'risk']):
                if current_vuln:
                    vulnerabilities.append(current_vuln)
                current_vuln = {"description": line}
            elif current_vuln and line:
                if "description" in current_vuln:
                    current_vuln["description"] += " " + line
        
        if current_vuln:
            vulnerabilities.append(current_vuln)
        
        result["vulnerabilities"] = vulnerabilities
    
    result["metadata"] = {
        "parsed_at": datetime.now().isoformat(),
        "text_length": len(text),
        "instructions": instructions or "No specific instructions provided"
    }
    
    return result

@mcp.tool()
def parse_pdf_from_github(
    github_url: str,
    output_format: str = "text",
    json_schema: Optional[Dict[str, Any]] = None,
    cache_enabled: bool = True
) -> Dict[str, Any]:
    """
    Parses PDF file from GitHub repository.
    
    Args:
        github_url: PDF file URL in GitHub repository
        output_format: Output format (text, json)
        json_schema: JSON schema for data structuring (only for json format)
        cache_enabled: Use caching of results
    
    Returns:
        Parsing result with text or JSON data
    """
    logger.info(f"Parsing PDF from GitHub: {github_url}")
    
    start_time = datetime.now()
    
    cache_key = get_cache_key(github_url, output_format)
    if cache_enabled and cache_key in parse_cache:
        logger.info("Using cached result")
        result = parse_cache[cache_key]
        result.processing_time = (datetime.now() - start_time).total_seconds()
        return result.dict()
    
    try:
        pdf_bytes = download_pdf(github_url)
        logger.info(f"Downloaded {len(pdf_bytes)} bytes")        
        text_content = parse_pdf_text(pdf_bytes)
        
        result = PDFParseResult(
            success=True,
            text_content=text_content,
            metadata={
                "url": github_url,
                "file_size": len(pdf_bytes),
                "text_length": len(text_content),
                "parsed_at": datetime.now().isoformat()
            }
        )
        
        if output_format == "json":
            if json_schema:
                json_content = convert_text_to_json_with_schema(text_content, json_schema)
                result.json_content = json_content
            else:
                result.json_content = {
                    "text": text_content,
                    "metadata": result.metadata
                }
        
        if cache_enabled:
            parse_cache[cache_key] = result
        
        result.processing_time = (datetime.now() - start_time).total_seconds()
        logger.info(f"Parsing completed in {result.processing_time:.2f} seconds")
        
        return result.dict()
        
    except Exception as e:
        logger.error(f"Parsing error: {e}")
        result = PDFParseResult(
            success=False,
            error=str(e),
            processing_time=(datetime.now() - start_time).total_seconds()
        )
        return result.dict()

@mcp.tool()
def parse_pdf_from_url(
    url: str,
    output_format: str = "text",
    json_schema: Optional[Dict[str, Any]] = None,
    cache_enabled: bool = True
) -> Dict[str, Any]:
    """
    Parses PDF file from any URL.
    
    Args:
        url: PDF file URL
        output_format: Output format (text, json)
        json_schema: JSON schema for data structuring
        cache_enabled: Use caching of results
    
    Returns:
        Parsing result with text or JSON data
    """
    return parse_pdf_from_github(url, output_format, json_schema, cache_enabled)

@mcp.tool()
def convert_text_to_json(
    text: str,
    json_schema: Dict[str, Any],
    instructions: Optional[str] = None
) -> Dict[str, Any]:
    """
    Converts text to JSON according to the given schema.
    
    Args:
        text: Text to convert
        json_schema: JSON schema for data structuring
        instructions: Additional instructions for processing
    
    Returns:
        JSON data according to schema
    """
    logger.info("Converting text to JSON")
    
    try:
        json_content = convert_text_to_json_with_schema(text, json_schema, instructions)
        
        result = TextToJsonResult(
            success=True,
            json_content=json_content
        )
        
        return result.dict()
        
    except Exception as e:
        logger.error(f"Conversion error: {e}")
        result = TextToJsonResult(
            success=False,
            error=str(e)
        )
        return result.dict()

@mcp.tool()
def get_cache_stats() -> Dict[str, Any]:
    """
    Returns parsing cache statistics.
    
    Returns:
        Cache statistics
    """
    return {
        "cache_size": len(parse_cache),
        "cached_urls": list(parse_cache.keys()),
        "total_processing_time": sum(r.processing_time for r in parse_cache.values())
    }

@mcp.tool()
def clear_cache() -> Dict[str, Any]:
    """
    Clears parsing cache.
    
    Returns:
        Cache clearing result
    """
    cache_size = len(parse_cache)
    parse_cache.clear()
    
    return {
        "success": True,
        "cleared_entries": cache_size,
        "message": f"Cleared {cache_size} entries from cache"
    }

if __name__ == "__main__":
    logger.info("Starting PDF Parser MCP server...")
    mcp.run(transport="stdio")
