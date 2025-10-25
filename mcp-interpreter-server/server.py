"""
MCP Server with Python Interpreter and Vulnerability Report Parsing Tools

This server provides:
1. Python code execution capabilities
2. Three specialized parsing tools for vulnerability reports:
   - parse_markdown_report: Parses Markdown vulnerability reports
   - parse_json_report: Parses JSON vulnerability reports  
   - parse_pdf_text: Parses PDF text (after markitdown conversion)

Each parser returns CVS (Canonical Vulnerability Schema) records and saves raw content.
"""

from mcp.server.fastmcp import FastMCP
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import json
import re
import uuid
import os
import argparse
from datetime import datetime
from pathlib import Path
import subprocess
import tempfile
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def parse_args():
    parser = argparse.ArgumentParser(description='MCP Vulnerability Report Parser Server')
    parser.add_argument('--data-dir', 
                       type=str, 
                       default='data',
                       help='Path to data directory containing raw, normalized, and index folders (default: data)')
    return parser.parse_args()

args = parse_args()

mcp = FastMCP("Vulnerability Report Parser with Python Interpreter")

class CVS(BaseModel):
    """Canonical Vulnerability Schema - standardized format for vulnerability data"""
    id: str = Field(description="Unique identifier for the vulnerability")
    title: str = Field(description="Vulnerability title")
    description: str = Field(description="Detailed description")
    severity: str = Field(description="Severity level (Critical/High/Medium/Low/Info)")
    impact: str = Field(description="Impact description")
    proof_of_concept: Optional[str] = Field(default=None, description="Proof of concept or exploit details")
    remediation: Optional[str] = Field(default=None, description="Remediation steps")
    tags: List[str] = Field(default_factory=list, description="Vulnerability tags/patterns")
    cwe: Optional[str] = Field(default=None, description="CWE identifier")
    references: List[str] = Field(default_factory=list, description="External references/links")
    raw_excerpt: str = Field(description="Raw text excerpt from source")
    source_path: str = Field(description="Path to raw content file")
    parsed_at: str = Field(description="Timestamp when parsed")

DATA_DIR = Path(args.data_dir).resolve()
RAW_DIR = DATA_DIR / "raw"
NORMALIZED_DIR = DATA_DIR / "normalized"
INDEX_DIR = DATA_DIR / "index"

logger.info(f"Using data directory: {DATA_DIR}")

RAW_DIR.mkdir(parents=True, exist_ok=True)
NORMALIZED_DIR.mkdir(parents=True, exist_ok=True)
INDEX_DIR.mkdir(parents=True, exist_ok=True)

def save_raw_content(content: str, content_type: str) -> str:
    """Save raw content to file and return the path"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    content_hash = str(uuid.uuid4())[:8]
    filename = f"{content_type}_{timestamp}_{content_hash}.txt"
    filepath = RAW_DIR / filename
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    return str(filepath)

def save_normalized_cvs(cvs_record: CVS) -> str:
    """Save normalized CVS record to JSON file"""
    filename = f"{cvs_record.id}.json"
    filepath = NORMALIZED_DIR / filename
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(cvs_record.dict(), f, indent=2, ensure_ascii=False)
    
    return str(filepath)

def extract_vulnerability_patterns(text: str) -> List[str]:
    """Extract vulnerability patterns from text"""
    patterns = {
        'reentrancy': r'(?i)(reentrancy|reentrant|reentrant attack)',
        'delegatecall': r'(?i)(delegatecall|delegate call)',
        'tx.origin': r'(?i)(tx\.origin|txorigin)',
        'access_control': r'(?i)(access control|authorization|permission|role)',
        'unchecked_call': r'(?i)(unchecked call|unchecked external call)',
        'integer_overflow': r'(?i)(integer overflow|overflow|underflow)',
        'front_running': r'(?i)(front running|front-running|mev)',
        'denial_of_service': r'(?i)(denial of service|dos|gas limit)',
        'timestamp_dependency': r'(?i)(timestamp|block\.timestamp|time dependency)',
        'randomness': r'(?i)(random|randomness|predictable)'
    }
    
    found_patterns = []
    for pattern_name, pattern_regex in patterns.items():
        if re.search(pattern_regex, text):
            found_patterns.append(pattern_name)
    
    return found_patterns

# Search and indexing functions
def normalize_token(token: str) -> str:
    """Normalize token for indexing"""
    return re.sub(r'[^\w]', '', token.lower().strip())

def is_security_relevant_token(token: str) -> bool:
    """Check if token is relevant for security analysis"""
    security_keywords = {
        # Vulnerability types
        'reentrancy', 'reentrant', 'overflow', 'underflow', 'delegatecall', 'delegate',
        'access', 'control', 'authorization', 'permission', 'role', 'admin', 'owner',
        'unchecked', 'external', 'call', 'origin', 'timestamp', 'block', 'random',
        'front', 'running', 'mev', 'dos', 'denial', 'service', 'gas', 'limit',
        'integer', 'arithmetic', 'division', 'modulo', 'exponentiation',
        
        # Attack vectors
        'attack', 'exploit', 'vulnerability', 'weakness', 'flaw', 'bug', 'issue',
        'malicious', 'attacker', 'adversary', 'hacker', 'exploiter',
        'injection', 'manipulation', 'bypass', 'circumvent', 'evade',
        
        # Security concepts
        'security', 'safe', 'unsafe', 'secure', 'insecure', 'protected', 'unprotected',
        'validated', 'unvalidated', 'verified', 'unverified', 'authenticated', 'unauthorized',
        'encrypted', 'unencrypted', 'signed', 'unsigned', 'hash', 'checksum',
        
        # Smart contract specific
        'contract', 'solidity', 'ethereum', 'evm', 'gas', 'wei', 'ether', 'token',
        'erc20', 'erc721', 'erc1155', 'nft', 'fungible', 'nonfungible',
        'fallback', 'receive', 'constructor', 'modifier', 'event', 'emit',
        'mapping', 'array', 'struct', 'enum', 'library', 'interface',
        
        # Financial terms
        'balance', 'transfer', 'withdraw', 'deposit', 'mint', 'burn', 'approve',
        'allowance', 'total', 'supply', 'price', 'value', 'amount', 'funds',
        
        # Technical terms that matter
        'state', 'storage', 'memory', 'calldata', 'stack', 'heap',
        'transaction', 'block', 'miner', 'validator', 'consensus',
        'network', 'node', 'peer', 'protocol', 'fork', 'upgrade'
    }
    
    return token in security_keywords

def build_inverted_index():
    """Build inverted index from normalized CVS files"""
    inverted_index = {}
    meta_data = {
        "built_at": datetime.now().isoformat(),
        "total_documents": 0,
        "total_tokens": 0
    }
    
    stop_words = {
        'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by',
        'is', 'are', 'was', 'were', 'be', 'been', 'have', 'has', 'had', 'do', 'does', 'did',
        'will', 'would', 'could', 'should', 'may', 'might', 'must', 'can',
        'this', 'that', 'these', 'those', 'i', 'you', 'he', 'she', 'it', 'we', 'they', 
        'me', 'him', 'her', 'us', 'them', 'my', 'your', 'his', 'her', 'its', 'our', 'their',
        'from', 'into', 'onto', 'upon', 'over', 'under', 'through', 'during', 'before', 'after',
        'very', 'just', 'only', 'also', 'even', 'still', 'yet', 'already', 'here', 'there',
        'good', 'bad', 'new', 'old', 'first', 'last', 'next', 'previous', 'same', 'different',
        'one', 'two', 'three', 'first', 'second', 'third', 'all', 'some', 'any', 'every', 'each',
        'function', 'method', 'class', 'object', 'variable', 'parameter', 'return', 'value',
        'code', 'file', 'data', 'information', 'content', 'text', 'string', 'number'
    }
    
    field_weights = {
        'title': 3,
        'description': 2,
        'impact': 2,
        'proof_of_concept': 1,
        'remediation': 1
    }
    
    for json_file in NORMALIZED_DIR.glob("*.json"):
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                cvs_data = json.load(f)
            
            doc_id = cvs_data['id']
            meta_data["total_documents"] += 1
            
            for field, weight in field_weights.items():
                if field in cvs_data and cvs_data[field]:
                    text = str(cvs_data[field])
                    tokens = re.findall(r'\b\w+\b', text.lower())
                    
                    for token in tokens:
                        normalized_token = normalize_token(token)
                     
                        if (normalized_token and len(normalized_token) > 2 and 
                            (normalized_token not in stop_words or is_security_relevant_token(normalized_token))):
                            if normalized_token not in inverted_index:
                                inverted_index[normalized_token] = []
                            
                            existing_entry = None
                            for entry in inverted_index[normalized_token]:
                                if entry['doc_id'] == doc_id and entry['field'] == field:
                                    existing_entry = entry
                                    break
                            
                            if existing_entry:
                                existing_entry['freq'] += 1
                            else:
                                inverted_index[normalized_token].append({
                                    'doc_id': doc_id,
                                    'field': field,
                                    'freq': 1,
                                    'weight': weight
                                })
                            
                            meta_data["total_tokens"] += 1
        
        except Exception as e:
            logger.error(f"Error processing {json_file}: {e}")
    
    index_file = INDEX_DIR / "inverted.json"
    with open(index_file, 'w', encoding='utf-8') as f:
        json.dump(inverted_index, f, indent=2, ensure_ascii=False)
    
    meta_file = INDEX_DIR / "meta.json"
    with open(meta_file, 'w', encoding='utf-8') as f:
        json.dump(meta_data, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Built inverted index with {len(inverted_index)} tokens from {meta_data['total_documents']} documents")
    return inverted_index, meta_data

def load_inverted_index():
    """Load inverted index from file"""
    index_file = INDEX_DIR / "inverted.json"
    if index_file.exists():
        with open(index_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def search_documents(query: str, fields: List[str] = None, limit: int = 20) -> List[Dict]:
    """Search documents using inverted index"""
    if fields is None:
        fields = ["title", "description", "impact", "proof_of_concept"]
    
    inverted_index = load_inverted_index()
    if not inverted_index:
        logger.warning("No inverted index found. Building index...")
        build_inverted_index()
        inverted_index = load_inverted_index()
    
    query_tokens = re.findall(r'\b\w+\b', query.lower())
    query_tokens = [normalize_token(token) for token in query_tokens if token and len(token) > 2]
    
    if not query_tokens:
        return []
    
    doc_scores = {}
    field_weights = {
        'title': 3,
        'description': 2,
        'impact': 2,
        'proof_of_concept': 1,
        'remediation': 1
    }
    
    for token in query_tokens:
        if token in inverted_index:
            for entry in inverted_index[token]:
                if entry['field'] in fields:
                    doc_id = entry['doc_id']
                    if doc_id not in doc_scores:
                        doc_scores[doc_id] = 0
                    
                    # Score calculation: token_weight * field_weight * log(1+freq)
                    score = entry['weight'] * field_weights[entry['field']] * (1 + entry['freq'])
                    doc_scores[doc_id] += score
    
    sorted_docs = sorted(doc_scores.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    results = []
    for doc_id, score in sorted_docs:
        try:
            doc_file = NORMALIZED_DIR / f"{doc_id}.json"
            if doc_file.exists():
                with open(doc_file, 'r', encoding='utf-8') as f:
                    doc_data = json.load(f)
                
                snippet_parts = []
                for field in fields:
                    if field in doc_data and doc_data[field]:
                        text = str(doc_data[field])
                        for token in query_tokens:
                            if token in text.lower():
                                start = max(0, text.lower().find(token) - 50)
                                end = min(len(text), text.lower().find(token) + 100)
                                snippet = text[start:end]
                                if snippet not in snippet_parts:
                                    snippet_parts.append(snippet)
                                break
                
                snippet = " ... ".join(snippet_parts[:2])  
                
                results.append({
                    'id': doc_id,
                    'title': doc_data.get('title', 'Unknown'),
                    'severity': doc_data.get('severity', 'Unknown'),
                    'tags': doc_data.get('tags', []),
                    'score': score,
                    'snippet': snippet,
                    'source_path': doc_data.get('source_path', '')
                })
        
        except Exception as e:
            logger.error(f"Error loading document {doc_id}: {e}")
    
    return results

@mcp.tool()
def execute_python(code: str) -> str:
    """
    Execute Python code and return the result.
    
    Args:
        code: Python code to execute
        
    Returns:
        Execution result or error message
    """
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_file = f.name
        
        result = subprocess.run(
            ['python', temp_file],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        os.unlink(temp_file)
        
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error: {result.stderr}"
            
    except subprocess.TimeoutExpired:
        return "Error: Code execution timed out"
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool()
def parse_markdown_report(md_text: str) -> str:
    """
    Parse Markdown vulnerability report and extract CVS records.
    
    Args:
        md_text: Markdown text content
        
    Returns:
        JSON string containing CVS records
    """
    try:
        raw_path = save_raw_content(md_text, "markdown_report")
        
        sections = {}
        
        title_match = re.search(r'^#\s+(.+)$', md_text, re.MULTILINE)
        if title_match:
            sections['title'] = title_match.group(1).strip()
        else:
            lines = md_text.strip().split('\n')
            sections['title'] = lines[0].strip() if lines else "Unknown Vulnerability"
        
        section_patterns = {
            'summary': r'(?i)(?:##?\s+)?(?:summary|overview|description)(?:\s*##?\s*)?\n(.*?)(?=\n##?\s+|\Z)',
            'impact': r'(?i)(?:##?\s+)?impact(?:\s*##?\s*)?\n(.*?)(?=\n##?\s+|\Z)',
            'proof_of_concept': r'(?i)(?:##?\s+)?(?:proof\s+of\s+concept|poc|exploit|example)(?:\s*##?\s*)?\n(.*?)(?=\n##?\s+|\Z)',
            'remediation': r'(?i)(?:##?\s+)?(?:remediation|fix|solution|recommendation)(?:\s*##?\s*)?\n(.*?)(?=\n##?\s+|\Z)',
            'severity': r'(?i)(?:##?\s+)?(?:severity|risk|level)(?:\s*##?\s*)?\n(.*?)(?=\n##?\s+|\Z)'
        }
        
        for section_name, pattern in section_patterns.items():
            match = re.search(pattern, md_text, re.DOTALL | re.MULTILINE)
            if match:
                sections[section_name] = match.group(1).strip()
        
        if 'severity' not in sections:
            severity_match = re.search(r'(?i)(critical|high|medium|low|info)', md_text)
            if severity_match:
                sections['severity'] = severity_match.group(1).title()
            else:
                sections['severity'] = "Unknown"
        
        tags = extract_vulnerability_patterns(md_text)
        
        links = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', md_text)
        references = [f"{text}: {url}" for text, url in links]
        
        cwe_match = re.search(r'(?i)cwe[-\s]*(\d+)', md_text)
        cwe = f"CWE-{cwe_match.group(1)}" if cwe_match else None
        
        cvs_record = CVS(
            id=str(uuid.uuid4()),
            title=sections.get('title', 'Unknown Vulnerability'),
            description=sections.get('summary', 'No description available'),
            severity=sections.get('severity', 'Unknown'),
            impact=sections.get('impact', 'Impact not specified'),
            proof_of_concept=sections.get('proof_of_concept'),
            remediation=sections.get('remediation'),
            tags=tags,
            cwe=cwe,
            references=references,
            raw_excerpt=md_text[:500] + "..." if len(md_text) > 500 else md_text,
            source_path=raw_path,
            parsed_at=datetime.now().isoformat()
        )
        
        save_normalized_cvs(cvs_record)
        
        return json.dumps([cvs_record.dict()], indent=2)
        
    except Exception as e:
        logger.error(f"Error parsing markdown report: {e}")
        return json.dumps([{"error": str(e)}], indent=2)

@mcp.tool()
def parse_json_report(json_obj: dict) -> str:
    """
    Parse JSON vulnerability report and extract CVS records.
    
    Args:
        json_obj: JSON object containing vulnerability data
        
    Returns:
        JSON string containing CVS records
    """
    try:
        json_text = json.dumps(json_obj, indent=2)
        raw_path = save_raw_content(json_text, "json_report")
        
        cvs_records = []
        
        if isinstance(json_obj, list):
            for item in json_obj:
                cvs_record = _parse_single_json_vulnerability(item, raw_path)
                if cvs_record:
                    cvs_records.append(cvs_record)
        else:
            cvs_record = _parse_single_json_vulnerability(json_obj, raw_path)
            if cvs_record:
                cvs_records.append(cvs_record)
        
        return json.dumps([record.dict() for record in cvs_records], indent=2)
        
    except Exception as e:
        logger.error(f"Error parsing JSON report: {e}")
        return json.dumps([{"error": str(e)}], indent=2)

def _parse_single_json_vulnerability(data: dict, raw_path: str) -> Optional[CVS]:
    """Parse a single vulnerability from JSON data"""
    try:
        field_mappings = {
            'title': ['title', 'name', 'vulnerability', 'issue'],
            'description': ['description', 'summary', 'details', 'overview'],
            'severity': ['severity', 'risk', 'level', 'priority'],
            'impact': ['impact', 'consequence', 'effect'],
            'proof_of_concept': ['proof_of_concept', 'poc', 'exploit', 'example'],
            'remediation': ['remediation', 'fix', 'solution', 'recommendation'],
            'tags': ['tags', 'categories', 'types', 'patterns'],
            'cwe': ['cwe', 'cwe_id', 'cwe_number'],
            'references': ['references', 'links', 'urls', 'sources']
        }
        
        extracted = {}
        for field, possible_keys in field_mappings.items():
            for key in possible_keys:
                if key in data:
                    extracted[field] = data[key]
                    break
        
        if 'tags' not in extracted and 'description' in extracted:
            tags = extract_vulnerability_patterns(extracted['description'])
        else:
            tags = extracted.get('tags', [])
        
        if isinstance(tags, str):
            tags = [tags]
        
        references = extracted.get('references', [])
        if isinstance(references, str):
            references = [references]
        
        cvs_record = CVS(
            id=str(uuid.uuid4()),
            title=extracted.get('title', 'Unknown Vulnerability'),
            description=extracted.get('description', 'No description available'),
            severity=extracted.get('severity', 'Unknown'),
            impact=extracted.get('impact', 'Impact not specified'),
            proof_of_concept=extracted.get('proof_of_concept'),
            remediation=extracted.get('remediation'),
            tags=tags,
            cwe=extracted.get('cwe'),
            references=references,
            raw_excerpt=json.dumps(data, indent=2)[:500] + "..." if len(json.dumps(data, indent=2)) > 500 else json.dumps(data, indent=2),
            source_path=raw_path,
            parsed_at=datetime.now().isoformat()
        )
        
        # Save normalized CVS record
        save_normalized_cvs(cvs_record)
        
        return cvs_record
        
    except Exception as e:
        logger.error(f"Error parsing single JSON vulnerability: {e}")
        return None

@mcp.tool()
def parse_pdf_text(txt_from_markitdown: str) -> str:
    """
    Parse PDF text (after markitdown conversion) and extract CVS records.
    
    Args:
        txt_from_markitdown: Text content extracted from PDF via markitdown
        
    Returns:
        JSON string containing CVS records
    """
    try:
        raw_path = save_raw_content(txt_from_markitdown, "pdf_text")
        
        sections = {}
        
        title_patterns = [
            r'(?i)title[:\s]+(.+?)(?:\n|$)',
            r'^(.+?)(?:\n|$)',  
        ]
        
        for pattern in title_patterns:
            match = re.search(pattern, txt_from_markitdown)
            if match:
                sections['title'] = match.group(1).strip()
                break
        
        if 'title' not in sections:
            sections['title'] = "Unknown Vulnerability"
        
        section_patterns = {
            'summary': r'(?i)(?:summary|overview|description|abstract)[:\s]*\n?(.*?)(?=\n(?:impact|severity|risk|vulnerability|proof|remediation|fix|solution)|\Z)',
            'impact': r'(?i)(?:impact|consequence|effect)[:\s]*\n?(.*?)(?=\n(?:severity|risk|vulnerability|proof|remediation|fix|solution)|\Z)',
            'proof_of_concept': r'(?i)(?:proof\s+of\s+concept|poc|exploit|example|demonstration)[:\s]*\n?(.*?)(?=\n(?:remediation|fix|solution|recommendation)|\Z)',
            'remediation': r'(?i)(?:remediation|fix|solution|recommendation|mitigation)[:\s]*\n?(.*?)(?=\n(?:reference|link|url)|\Z)',
            'severity': r'(?i)(?:severity|risk\s+level|priority)[:\s]*\n?(.*?)(?=\n(?:impact|vulnerability|proof|remediation)|\Z)'
        }
        
        for section_name, pattern in section_patterns.items():
            match = re.search(pattern, txt_from_markitdown, re.DOTALL | re.MULTILINE)
            if match:
                sections[section_name] = match.group(1).strip()
        
        if 'severity' not in sections:
            severity_match = re.search(r'(?i)(critical|high|medium|low|info)', txt_from_markitdown)
            if severity_match:
                sections['severity'] = severity_match.group(1).title()
            else:
                sections['severity'] = "Unknown"
        
        tags = extract_vulnerability_patterns(txt_from_markitdown)
        
        url_pattern = r'https?://[^\s]+'
        urls = re.findall(url_pattern, txt_from_markitdown)
        references = list(set(urls))  
        
        cwe_match = re.search(r'(?i)cwe[-\s]*(\d+)', txt_from_markitdown)
        cwe = f"CWE-{cwe_match.group(1)}" if cwe_match else None
        
        cvs_record = CVS(
            id=str(uuid.uuid4()),
            title=sections.get('title', 'Unknown Vulnerability'),
            description=sections.get('summary', 'No description available'),
            severity=sections.get('severity', 'Unknown'),
            impact=sections.get('impact', 'Impact not specified'),
            proof_of_concept=sections.get('proof_of_concept'),
            remediation=sections.get('remediation'),
            tags=tags,
            cwe=cwe,
            references=references,
            raw_excerpt=txt_from_markitdown[:500] + "..." if len(txt_from_markitdown) > 500 else txt_from_markitdown,
            source_path=raw_path,
            parsed_at=datetime.now().isoformat()
        )
        
        save_normalized_cvs(cvs_record)
        
        return json.dumps([cvs_record.dict()], indent=2)
        
    except Exception as e:
        logger.error(f"Error parsing PDF text: {e}")
        return json.dumps([{"error": str(e)}], indent=2)

@mcp.tool()
def list_vulns(severity_filter: Optional[List[str]] = None, weakness_filter: Optional[List[str]] = None, since: Optional[str] = None) -> str:
    """
    List vulnerabilities with optional filters.
    
    Args:
        severity_filter: List of severity levels to filter by (Critical, High, Medium, Low, Info)
        weakness_filter: List of weakness patterns to filter by (reentrancy, access_control, etc.)
        since: ISO8601 timestamp to filter vulnerabilities parsed after this date
        
    Returns:
        JSON string containing list of vulnerabilities with id, title, severity, weakness[], source.uri
    """
    try:
        results = []
        
        for json_file in NORMALIZED_DIR.glob("*.json"):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    cvs_data = json.load(f)
                
                if severity_filter and cvs_data.get('severity', '').lower() not in [s.lower() for s in severity_filter]:
                    continue
                
                if weakness_filter and not any(weakness.lower() in [tag.lower() for tag in cvs_data.get('tags', [])] for weakness in weakness_filter):
                    continue
                
                if since:
                    parsed_at = cvs_data.get('parsed_at', '')
                    if parsed_at and parsed_at < since:
                        continue
                
                source_uri = cvs_data.get('source_path', '')
                if source_uri.startswith('data/raw/'):
                    source_uri = f"file://{source_uri}"
                
                results.append({
                    'id': cvs_data.get('id', ''),
                    'title': cvs_data.get('title', 'Unknown'),
                    'severity': cvs_data.get('severity', 'Unknown'),
                    'weakness': cvs_data.get('tags', []),
                    'source': {'uri': source_uri}
                })
            
            except Exception as e:
                logger.error(f"Error processing {json_file}: {e}")
        
        return json.dumps(results, indent=2)
        
    except Exception as e:
        logger.error(f"Error listing vulnerabilities: {e}")
        return json.dumps([{"error": str(e)}], indent=2)

@mcp.tool()
def keyword_search(query: str, fields: Optional[List[str]] = None, limit: int = 20) -> str:
    """
    Search vulnerabilities using keyword search with inverted index.
    
    Args:
        query: Search query string
        fields: List of fields to search in (title, description, impact, proof_of_concept, remediation)
        limit: Maximum number of results to return
        
    Returns:
        JSON string containing search results with snippets
    """
    try:
        if fields is None:
            fields = ["title", "description", "impact", "proof_of_concept"]
        
        results = search_documents(query, fields, limit)
        return json.dumps(results, indent=2)
        
    except Exception as e:
        logger.error(f"Error in keyword search: {e}")
        return json.dumps([{"error": str(e)}], indent=2)

@mcp.tool()
def get_vuln(vuln_id: str) -> str:
    """
    Get full vulnerability details by ID.
    
    Args:
        vuln_id: Vulnerability ID
        
    Returns:
        JSON string containing full CVS record
    """
    try:
        doc_file = NORMALIZED_DIR / f"{vuln_id}.json"
        if not doc_file.exists():
            return json.dumps({"error": f"Vulnerability {vuln_id} not found"}, indent=2)
        
        with open(doc_file, 'r', encoding='utf-8') as f:
            cvs_data = json.load(f)
        
        return json.dumps(cvs_data, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting vulnerability {vuln_id}: {e}")
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
def stats() -> str:
    """
    Get vulnerability statistics.
    
    Returns:
        JSON string containing count, by_severity, by_weakness statistics
    """
    try:
        stats_data = {
            "count": 0,
            "by_severity": {},
            "by_weakness": {}
        }
        
        for json_file in NORMALIZED_DIR.glob("*.json"):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    cvs_data = json.load(f)
                
                stats_data["count"] += 1
                
                severity = cvs_data.get('severity', 'Unknown')
                stats_data["by_severity"][severity] = stats_data["by_severity"].get(severity, 0) + 1
                
                tags = cvs_data.get('tags', [])
                for tag in tags:
                    stats_data["by_weakness"][tag] = stats_data["by_weakness"].get(tag, 0) + 1
            
            except Exception as e:
                logger.error(f"Error processing {json_file}: {e}")
        
        return json.dumps(stats_data, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
def rebuild_index() -> str:
    """
    Rebuild the inverted index from normalized CVS files.
    
    Returns:
        JSON string with index building results
    """
    try:
        inverted_index, meta_data = build_inverted_index()
        
        result = {
            "status": "success",
            "index_stats": meta_data,
            "message": f"Index rebuilt with {len(inverted_index)} tokens from {meta_data['total_documents']} documents"
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        logger.error(f"Error rebuilding index: {e}")
        return json.dumps({"error": str(e)}, indent=2)

if __name__ == "__main__":
    logger.info(f"Starting MCP server with data directory: {DATA_DIR}")
    logger.info(f"Raw directory: {RAW_DIR}")
    logger.info(f"Normalized directory: {NORMALIZED_DIR}")
    logger.info(f"Index directory: {INDEX_DIR}")
    mcp.run(transport="stdio")
