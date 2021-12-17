import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as f:
    requirements = f.readlines()

setuptools.setup(
    name="reactive-tools",
    version="0.5.2",
    author="Gianluca Scopelliti",
    author_email="gianlu.1033@gmail.com",
    description="Deployment tools for the Authentic Execution framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AuthenticExecution/reactive-tools",
    packages=setuptools.find_packages(),
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': ['reactive-tools = reactivetools.cli:main']
    },
    include_package_data=True
)
