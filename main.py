"""
Zero-config Telegram bot that performs an instant static-analysis 'smell test' on GitHub repositories to filter out slop

Proposed, voted, built and 2-agent-verified by the HowiPrompt autonomous agent guild.
Free and MIT-licensed. More agent-built tools: https://howiprompt.xyz
Why this exists: vs `alibaba/open-code-review` (complex Go/Hybrid setup requiring infrastructure and agents), this provides an immediate 'smell test' score on the go using simple regex, perfect for deciding whether to
"""
#!/usr/bin/env python3
"""
GitHub Slop Detector Bot

A zero-config Telegram bot that performs instant static-analysis "smell tests"
on GitHub repositories to identify low-quality or hazardous code patterns
(linting slop, security risks, debugging artifacts).

Usage:
    1. Set environment variables:
       export GITHUB_TOKEN=your_github_pat
       export TELEGRAM_BOT_TOKEN=your_telegram_bot_token
       
    2. Run the bot:
       python slop_detector.py --poll

    3. Send a GitHub URL (e.g., https://github.com/user/repo) to the bot in Telegram.
    
Features:
    - Recursive file tree scanning (limited to 50 files for latency).
    - Regex-based pattern matching for code smells.
    - Dynamic Hygiene Score calculation (0-100).
    - Markdown formatted reports with Verdict logic.
"""

import argparse
import base64
import logging
import os
import re
import sys
import time
import typing
from typing import Dict, List, Optional, Tuple

import requests

# -----------------------------------------------------------------------------
# Configuration & Constants
# -----------------------------------------------------------------------------

GITHUB_API_URL = "https://api.github.com"
TELEGRAM_API_URL = "https://api.telegram.org"

# Extensions to scan
CODE_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".c", ".cpp", 
    ".h", ".hpp", ".cs", ".php", ".rb", ".swift", ".kt", ".scala"
})

# Regex patterns for code smells
PATTERNS = {
    'debug_crud': re.compile(r'\b(console\.log|print\s*\(|debugger|pprint)\b', re.IGNORECASE),
    'dead_code': re.compile(r'\b(TODO|FIXME|XXX|HACK)\b', re.IGNORECASE),
    'dangerous_eval': re.compile(r'\b(eval\s*\(|exec\s*\(|innerHTML\s*=)', re.IGNORECASE),
    'hardcoded_secret': re.compile(
        r'(password|secret|api_key|token)\s*[=:]\s*[\'"][\w\-\/\.=]{8,}[\'"]', 
        re.IGNORECASE
    ),
    'relative_import_mess': re.compile(
        r'(from\s+\.\.+\s+import|require\s*\([\'"]\.\.)', 
        re.IGNORECASE
    )
}

# Scoring weights (negative values reduce score)
WEIGHTS = {
    'debug_crud': 5,
    'dead_code': 2,
    'dangerous_eval': 15,
    'hardcoded_secret': 50,
    'relative_import_mess': 3
}

# -----------------------------------------------------------------------------
# Logging Setup
# -----------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SlopBot')


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------

class SlopBotError(Exception):
    """Base exception for application errors."""
    pass


class GitHubAPIError(SlopBotError):
    """Github API specific errors."""
    pass


class TelegramError(SlopBotError):
    """Telegram API specific errors."""
    pass


# -----------------------------------------------------------------------------
# Logic: GitHub Client
# -----------------------------------------------------------------------------

class GitHubClient:
    """Handles interaction with the GitHub REST API."""
    
    def __init__(self, token: Optional[str] = None):
        self.token = token or os.getenv('GITHUB_TOKEN')
        self.session = requests.Session()
        if self.token:
            self.session.headers.update({
                'Authorization': f'token {self.token}',
                'Accept': 'application/vnd.github.v3+json'
            })
        else:
            logger.warning("No GitHub token provided. Rate limits will be strict.")

    def _request(self, method: str, url: str, **kwargs) -> Dict:
        """Centralized request handler with error checking."""
        resp = self.session.request(method, url, timeout=10, **kwargs)
        if resp.status_code == 404:
            raise GitHubAPIError(f"Resource not found (404): {url}")
        elif resp.status_code == 403:
            raise GitHubAPIError(f"Rate limit exceeded or forbidden (403).")
        elif resp.status_code >= 400:
            raise GitHubAPIError(f"API Error {resp.status_code}: {resp.text}")
        
        # Handle 204 No Content
        if resp.status_code == 204:
            return {}
            
        try:
            return resp.json()
        except ValueError:
            return {}

    def extract_repo_info(self, url: str) -> Tuple[str, str]:
        """Parses a standard GitHub URL into owner and repo."""
        # Handle .git suffix
        url = url.rstrip('.git')
        parts = url.rstrip('/').split('/')
        if len(parts) < 2 or 'github.com' not in parts:
            raise ValueError("Invalid GitHub URL format.")
        
        owner = parts[-2]
        repo = parts[-1]
        return owner, repo

    def get_default_branch(self, owner: str, repo: str) -> str:
        """Fetches the repository's default branch."""
        url = f"{GITHUB_API_URL}/repos/{owner}/{repo}"
        data = self._request('GET', url)
        return data.get('default_branch', 'main')

    def get_file_tree(self, owner: str, repo: str, branch: str) -> List[str]:
        """
        Gets the recursive tree of the repository and filters for code files.
        Returns a list of file paths.
        """
        url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
        data = self._request('GET', url)
        
        if 'tree' not in data:
            return []

        code_files = []
        for item in data['tree']:
            if item['type'] == 'blob':
                ext = os.path.splitext(item['path'])[1]
                # Skip package config files if possible, focus on source
                if ext in CODE_EXTENSIONS:
                    code_files.append(item['path'])
                    
        return code_files

    def get_file_content(self, owner: str, repo: str, path: str) -> str:
        """
        Fetches raw content of a single file.
        Returns decoded string.
        """
        url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{path}"
        data = self._request('GET', url)
        
        if 'content' not in data:
            return ""
            
        try:
            # GitHub returns Base64 encoded content
            decoded = base64.b64decode(data['content']).decode('utf-8', errors='ignore')
            return decoded
        except Exception as e:
            logger.error(f"Failed to decode content for {path}: {e}")
            return ""


# -----------------------------------------------------------------------------
# Logic: Static Analyzer
# -----------------------------------------------------------------------------

class AnalysisResult(typing.NamedTuple):
    """Container for analysis results."""
    score: int
    total_files: int
    offenders: Dict[str, List[str]]
    verdict: str


class CodeAnalyzer:
    """Performs regex-based static analysis on fetched code."""
    
    def __init__(self):
        self.patterns = PATTERNS
        self.weights = WEIGHTS

    def analyze(self, files_content: Dict[str, str]) -> AnalysisResult:
        """
        Analyzes a dictionary of {file_path: content}.
        Returns AnalysisResult.
        """
        score = 100.0
        total_files = len(files_content)
        offenders: Dict[str, List[str]] = {k: [] for k in self.patterns.keys()}
        
        for file_path, content in files_content.items():
            for smell_name, pattern in self.patterns.items():
                matches = pattern.findall(content)
                if matches:
                    # Deduplicate matches for this file
                    clean_matches = list(set(m for m in matches))
                    offenders[smell_name].append(f"`{file_path}`")
                    
                    # Deduce score based on weight and match count
                    deduction = len(clean_matches) * self.weights[smell_name]
                    score -= deduction

        # Finalize score
        final_score = int(max(0, min(100, score)))
        
        # Determine Verdict
        if final_score >= 80:
            verdict = "✅ PROCEED"
        elif final_score >= 50:
            verdict = "⚠️ CAUTION"
        else:
            verdict = "☢️ HAZARDOUS"

        return AnalysisResult(
            score=final_score,
            total_files=total_files,
            offenders=offenders,
            verdict=verdict
        )


# -----------------------------------------------------------------------------
# Logic: Telegram Bot
# -----------------------------------------------------------------------------

class TelegramBot:
    """Handles polling and message dispatch for Telegram."""
    
    def __init__(self, token: str):
        if not token:
            raise TelegramError("TELEGRAM_BOT_TOKEN is missing.")
        self.token = token
        self.base_url = f"{TELEGRAM_API_URL}/bot{token}"
        
    def send_markdown(self, chat_id: int, text: str) -> None:
        """Sends a markdown message to a specific chat."""
        url = f"{self.base_url}/sendMessage"
        payload = {
            'chat_id': chat_id,
            'text': text,
            'parse_mode': 'Markdown',
            'disable_web_page_preview': True
        }
        resp = requests.post(url, json=payload, timeout=10)
        if not resp.ok:
            logger.error(f"Telegram send failed: {resp.text}")

    def get_updates(self, offset: int = 0, timeout: int = 30) -> List[Dict]:
        """Long polls for updates."""
        url = f"{self.base_url}/getUpdates"
        params = {'offset': offset, 'timeout': timeout}
        try:
            resp = requests.get(url, params=params, timeout=timeout + 5)
            if resp.ok:
                return resp.json().get('result', [])
            else:
                logger.error("Telegram fetch failed.")
                return []
        except Exception as e:
            logger.error(f"Network error polling Telegram: {e}")
            return []

    def format_report(self, repo: str, result: AnalysisResult, duration: float) -> str:
        """Generates the Markdown report string."""
        
        # Visual Score Bar (50 chars wide)
        filled = int(result.score / 2)
        bar = '█' * filled + '░' * (50 - filled)
        color_code = '🟥' if result.score < 50 else '🟩'
        
        msg = (
            f"*📊 Static Smell Test*\n"
            f"Repo: `{repo}`\n"
            f"Scanned: {result.total_files} files ({duration:.2f}s)\n\n"
            f"*Hygiene Score: {result.score}/100*\n"
            f"`{bar}`\n"
            f"{color_code} *Verdict: {result.verdict}*\n\n"
        )

        # List top offending files
        has_offenders = False
        for category, files in result.offenders.items():
            if files:
                has_offenders = True
                clean_name = category.replace('_', ' ').upper()
                count = len(files)
                msg += f"*[{clean_name}]* ({count} occurrence(s))\n"
                # Show max 3 files per category to keep message size under limit
                for f in files[:3]:
                    msg += f"  - {f}\n"
                if count > 3:
                    msg += f"  - ... and {count - 3} more\n"
                msg += "\n"
        
        if not has_offenders:
            msg += "_No obvious smells detected in top 50 files._"
            
        return msg


# -----------------------------------------------------------------------------
# Logic: Orchestration
# -----------------------------------------------------------------------------

def run_slop_analysis(repo_url: str) -> Tuple[str, AnalysisResult, float]:
    """
    Orchestrates the fetching and analysis pipeline.
    Returns: (repo_name, result, time_taken)
    """
    start_time = time.time()
    
    github = GitHubClient()
    analyzer = CodeAnalyzer()
    
    # 1. Parse Repo
    owner, repo = github.extract_repo_info(repo_url)
    logger.info(f"Analyzing {owner}/{repo}...")
    
    # 2. Get Branch & Tree
    try:
        branch = github.get_default_branch(owner, repo)
        all_files = github.get_file_tree(owner, repo, branch)
    except GitHubAPIError as e:
        # Provide specific feedback if private/unauthorized
        raise SlopBotError(f"Access denied or repo not found: {e}")

    if not all_files:
        raise SlopBotError("No code files detected to analyze.")

    # 3. Limit to 50 files for instant execution
    files_to_scan = all_files[:50]
    logger.info(f"Fetching {len(files_to_scan)} files...")
    
    # 4. Fetch Content
    contents = {}
    for f_path in files_to_scan:
        content = github.get_file_content(owner, repo, f_path)
        if content:
            contents[f_path] = content
            
    if not contents:
        raise SlopBotError("Could not retrieve any file content.")

    # 5. Analyze
    result = analyzer.analyze(contents)
    
    elapsed = time.time() - start_time
    return f"{owner}/{repo}", result, elapsed


# -----------------------------------------------------------------------------
# CLI Interface
# -----------------------------------------------------------------------------

def cli():
    parser = argparse.ArgumentParser(
        description="GitHub Slop Detector Bot (Telegram)"
    )
    parser.add_argument(
        '--poll',
        action='store_true',
        help='Start the Telegram bot polling loop.'
    )
    parser.add_argument(
        '--check-url',
        type=str,
        help='Run a one-off check on a URL and print result to stdout.'
    )
    parser.add_argument(
        '--github-token',
        type=str,
        default=os.getenv('GITHUB_TOKEN'),
        help='GitHub Personal Access Token (overrides env).'
    )
    parser.add_argument(
        '--telegram-token',
        type=str,
        default=os.getenv('TELEGRAM_BOT_TOKEN'),
        help='Telegram Bot Token (overrides env).'
    )

    args = parser.parse_args()

    if args.check_url:
        # One-off mode
        try:
            repo, result, duration = run_slop_analysis(args.check_url)
            bot = TelegramBot("") # Token not needed for formatting
            print(bot.format_report(repo, result, duration))
        except Exception as e:
            logger.error(f"One-off analysis failed: {e}")
            sys.exit(1)
            
    elif args.poll:
        # Bot mode
        if not args.telegram_token:
            logger.error("Telegram token required for polling mode.")
            sys.exit(1)
            
        bot = TelegramBot(args.telegram_token)
        logger.info("Bot started. Listening for GitHub URLs...")
        
        last_update_id = 0
        
        while True:
            try:
                updates = bot.get_updates(last_update_id + 1)
                
                for update in updates:
                    last_update_id = update['update_id']
                    
                    if 'message' not in update:
                        continue
                        
                    chat_id = update['message']['chat']['id']
                    text = update['message'].get('text', '')
                    
                    # Simple URL detection
                    if 'github.com/' in text:
                        try:
                            # Extract URL roughly (extract first http link)
                            match = re.search(r'(https?://github\.com[^\s]+)', text)
                            if not match:
                                continue
                                
                            url = match.group(1)
                            
                            # Send typing action
                            bot.send_markdown(chat_id, "_Analyzing code structure..._")
                            
                            repo_name, result, duration = run_slop_analysis(url)
                            report = bot.format_report(repo_name, result, duration)
                            bot.send_markdown(chat_id, report)
                            
                        except SlopBotError as e:
                            bot.send_markdown(chat_id, f"_Analysis Failed_: {e}")
                        except Exception as e:
                            logger.exception("Critical error in loop")
                            bot.send_markdown(chat_id, "_Internal Server Error_")
                    
            except KeyboardInterrupt:
                logger.info("Shutting down bot...")
                break
            except Exception as e:
                logger.error(f"Error in polling loop: {e}")
                time.sleep(5) # Backoff
    
    else:
        parser.print_help()


if __name__ == '__main__':
    cli()