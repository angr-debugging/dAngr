import pathlib
import pkg_resources
from setuptools import setup, find_packages

with pathlib.Path('requirements.txt').open() as requirements_txt:
    install_requires = [
        str(requirement)
        for requirement
        in pkg_resources.parse_requirements(requirements_txt)
    ]

setup(
    name='dAngr',  # Specify the name of your module
    version='1.0.0',
    author='Jorn Lapon, Dairo de Ruck, Victor Goeman, Vincent Naessens',
    author_email='jorn.lapon@kuleuven.be',
    license='MIT',
    package_dir={'': 'src'},
    description='A debugger for angr',
    entry_points={
        'console_scripts': [
            'dAngr = dAngr.run:run'
        ]
    },
    install_requires=install_requires,
    include_package_data=True,
    python_requires='>=3.10',

)