
from mcp.server.fastmcp import FastMCP
from pathlib import Path
import json, re, time, os
from typing import Dict, List, Any, Optional
import jsonpointer
import logging

mcp = FastMCP("Vulnerabilities reader")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

project_manager = get_project_manager()


if __name__ == "__main__":
    mcp.run(transport="streamable-http")  