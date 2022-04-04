from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf8") as f:
    readme = f.read()

with open("requirements.txt", "r", encoding="utf8") as f:
    requirements = [line.strip() for line in f.readlines() if line.strip()]

setup(
    name="fiberfox",
    version="0.2.4",
    packages=find_packages(),
    data_files=[],
    entry_points={
        "console_scripts": [
            "fiberfox = fiberfox.main:run",
        ]
    },
    install_requires=requirements,
    author="Oleksii Kachaiev",
    author_email="kachayev@gmail.com",
    description="High-performance DDoS vulnerability testing toolkit. Various L4/7 attack vectors. Async networking.",
    long_description=readme,
    long_description_content_type="text/markdown",
    url="https://github.com/kachayev/fiberfox",
    keywords=["network"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
    ],
    license="MIT",
    python_requires=">=3.8",
    include_package_data=True
)
