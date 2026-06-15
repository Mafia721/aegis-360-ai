from setuptools import setup, find_packages

setup(
    name="surfacezero",
    version="2.1.0",
    description="Pre-Authentication Attack Surface Enumeration Tool with AI Analyst",
    long_description=(
        "SurfaceZero - Pre-login attack surface scanner with AI-powered threat modeling, "
        "kill chain analysis, MITRE ATT&CK mapping, and unauthenticated API data harvesting. "
        "For authorized penetration testing only."
    ),
    author="SJ / BinaryGalaxys Security",
    url="https://binarygalaxys.com",
    packages=find_packages(),
    py_modules=["preloginscan"],
    install_requires=[
        "click>=8.0",
        "httpx>=0.23.0",
        "rich>=13.0",
        "beautifulsoup4>=4.12",
        "lxml>=4.9",
        "pyyaml>=6.0",
        "requests>=2.28",
        "anthropic>=0.50.0",
        "openai>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "surfacezero=preloginscan:cli",
        ],
    },
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
