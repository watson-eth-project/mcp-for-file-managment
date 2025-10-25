
from mcp.server.fastmcp import FastMCP
from pathlib import Path
import json, re, time, os
from typing import Dict, List, Any, Optional
import jsonpointer
import logging

mcp = FastMCP("Vulnerabilities reader")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



if __name__ == "__main__":
    mcp.settings.host = "0.0.0.0"
    mcp.run(transport="streamable-http")  
