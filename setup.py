"""AGENT ANONMUSK — Autonomous Bug Bounty Agent."""

from setuptools import setup, find_packages

setup(
    name="anonmusk-agent",
    version="1.0.0",
    description="Agent AnonMusk — Autonomous Bug Bounty Agent with Recon-Reason-Act Loop",
    author="Royal",
    python_requires=">=3.10",
    packages=find_packages(exclude=["tests*"]),
    entry_points={
        "console_scripts": [
            "anonmusk_agent=AnonMusk_agent:main",
        ],
    },
    install_requires=[
        "requests>=2.31.0",
        "httpx[http2]>=0.27.0",
        "aiohttp>=3.9.0",
        "beautifulsoup4>=4.12.0",
        "pyyaml>=6.0.1",
        "jinja2>=3.1.3",
        "python-dotenv>=1.0.1",
        "rich>=13.7.0",
        "colorama>=0.4.6",
        "pydantic>=2.6.0",
        "openai>=1.30.0",
        "anthropic>=0.25.0",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3.10",
    ],
)
