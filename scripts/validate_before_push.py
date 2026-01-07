#!/usr/bin/env python3
"""
Pre-push validation script for Sentinel3
Run this before pushing to catch issues that would fail CI/CD

Usage:
    python scripts/validate_before_push.py
    
Or add to git hooks:
    cp scripts/validate_before_push.py .git/hooks/pre-push
    chmod +x .git/hooks/pre-push
"""

import sys
import os
import subprocess
import ast
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header():
    print(f"""
{Colors.BLUE}{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗
║           SENTINEL3 PRE-PUSH VALIDATION                      ║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
""")

def check_python_syntax():
    """Check Python files for syntax errors"""
    print(f"{Colors.BLUE}[1/5] Checking Python syntax...{Colors.RESET}")
    
    errors = []
    py_files = list(PROJECT_ROOT.glob("src/**/*.py"))
    
    for py_file in py_files:
        try:
            with open(py_file, 'r') as f:
                source = f.read()
            ast.parse(source)
        except SyntaxError as e:
            errors.append(f"  {py_file.relative_to(PROJECT_ROOT)}: {e}")
    
    if errors:
        print(f"{Colors.RED}  ❌ Syntax errors found:{Colors.RESET}")
        for error in errors:
            print(f"     {error}")
        return False
    
    print(f"{Colors.GREEN}  ✅ {len(py_files)} Python files OK{Colors.RESET}")
    return True

def check_imports():
    """Check critical imports work"""
    print(f"{Colors.BLUE}[2/5] Checking critical imports...{Colors.RESET}")
    
    imports_to_check = [
        ("src.api.server", "create_app"),
        ("src.api.routes", "router"),
        ("src.query.lucene_parser", "execute_lucene_query"),
        ("src.shared_state", "monitor_state"),
    ]
    
    errors = []
    
    for module, attr in imports_to_check:
        try:
            # Suppress logging during import check
            import logging
            logging.disable(logging.CRITICAL)
            
            mod = __import__(module, fromlist=[attr])
            getattr(mod, attr)
            
            logging.disable(logging.NOTSET)
        except Exception as e:
            errors.append(f"  from {module} import {attr}: {e}")
    
    if errors:
        print(f"{Colors.RED}  ❌ Import errors:{Colors.RESET}")
        for error in errors:
            print(f"     {error}")
        return False
    
    print(f"{Colors.GREEN}  ✅ All critical imports OK{Colors.RESET}")
    return True

def check_tests():
    """Run pytest"""
    print(f"{Colors.BLUE}[3/5] Running tests...{Colors.RESET}")
    
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-v", "-p", "no:anchorpy", "--tb=short"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"{Colors.RED}  ❌ Tests failed:{Colors.RESET}")
        # Show last few lines of output
        lines = result.stdout.split('\n')[-20:]
        for line in lines:
            if line.strip():
                print(f"     {line}")
        return False
    
    # Count passed tests
    import re
    match = re.search(r'(\d+) passed', result.stdout)
    passed = match.group(1) if match else "?"
    
    print(f"{Colors.GREEN}  ✅ {passed} tests passed{Colors.RESET}")
    return True

def check_dockerfile():
    """Validate Dockerfile can build"""
    print(f"{Colors.BLUE}[4/5] Validating Dockerfile...{Colors.RESET}")
    
    dockerfile = PROJECT_ROOT / "Dockerfile"
    if not dockerfile.exists():
        print(f"{Colors.RED}  ❌ Dockerfile not found{Colors.RESET}")
        return False
    
    # Check for common issues
    with open(dockerfile, 'r') as f:
        content = f.read()
    
    issues = []
    
    if "FROM" not in content:
        issues.append("Missing FROM instruction")
    
    if "COPY requirements.txt" not in content:
        issues.append("Missing COPY requirements.txt")
    
    if issues:
        print(f"{Colors.RED}  ❌ Dockerfile issues:{Colors.RESET}")
        for issue in issues:
            print(f"     {issue}")
        return False
    
    print(f"{Colors.GREEN}  ✅ Dockerfile looks valid{Colors.RESET}")
    return True

def check_requirements():
    """Check requirements.txt is valid"""
    print(f"{Colors.BLUE}[5/5] Checking requirements.txt...{Colors.RESET}")
    
    req_file = PROJECT_ROOT / "requirements.txt"
    if not req_file.exists():
        print(f"{Colors.RED}  ❌ requirements.txt not found{Colors.RESET}")
        return False
    
    with open(req_file, 'r') as f:
        lines = f.readlines()
    
    issues = []
    packages = 0
    
    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        packages += 1
        
        # Check for common issues
        if ' ' in line and not line.startswith('#'):
            issues.append(f"Line {i}: Unexpected space in '{line}'")
    
    if issues:
        print(f"{Colors.YELLOW}  ⚠️  Requirements warnings:{Colors.RESET}")
        for issue in issues:
            print(f"     {issue}")
    
    print(f"{Colors.GREEN}  ✅ {packages} packages in requirements.txt{Colors.RESET}")
    return True

def main():
    print_header()
    
    all_passed = True
    
    # Run all checks
    checks = [
        check_python_syntax,
        check_imports,
        check_tests,
        check_dockerfile,
        check_requirements,
    ]
    
    for check in checks:
        try:
            if not check():
                all_passed = False
        except Exception as e:
            print(f"{Colors.RED}  ❌ Check failed with exception: {e}{Colors.RESET}")
            all_passed = False
    
    # Summary
    print()
    if all_passed:
        print(f"{Colors.GREEN}{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗")
        print(f"║  ✅ ALL CHECKS PASSED - Safe to push!                        ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Colors.RESET}")
        return 0
    else:
        print(f"{Colors.RED}{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗")
        print(f"║  ❌ VALIDATION FAILED - Fix issues before pushing             ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Colors.RESET}")
        return 1

if __name__ == "__main__":
    sys.exit(main())

