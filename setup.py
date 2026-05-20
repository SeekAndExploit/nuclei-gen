from setuptools import setup, find_packages

setup(
    name="nuclei-gen",
    version="0.1.0",
    packages=find_packages(),
    install_requires=["PyYAML>=6.0"],
    entry_points={
        "console_scripts": [
            "nuclei-gen=nuclei_gen.cli:main",
        ]
    },
    python_requires=">=3.9",
)
