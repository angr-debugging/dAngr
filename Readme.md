# dAngr - A Debugger for Angr

dAngr offers a streamlined approach to leverage [angr's](https://angr.io) powerful symbolic execution capabilities within a user-friendly command-line interface (CLI) environment, eliminating the necessity for extensive programming knowledge usually required to use angr. 
Providing powerful capabilities for analyzing and debugging binaries.

## Features

- Perform symbolic execution on binaries for debugging purposes.
- Command-line interface for easy interaction.
- Easy way to call a function with chosen arguments without the hassle of memory management and argument parsing.
- Platform independent execution

## Installation


To use dAngr, follow these steps:

0. Preferable create a virtual environment, for instance using [venv](https://docs.python.org/3/library/venv.html).

1. Install the required dependencies by running the following command:

```bash
pip install .
```
Note: on MacOS you may need to run the following for now:
```bash
pip install --pre --no-binary capstone capstone==5.0.0.post1
```

2. Run dAngr:

```bash
dAngr
```

### Docker

For simplicity dAngr is also available using a Dockerfile.

Build Dockerfile to create an clean environment for dAngr.
```bash
docker build -t dAngr .
```

Run the Docker image and get the dAngr command prompt.
```bash
docker run -it dAngr
```

If you wish to run the dAngr Docker on your own binaries, you may need use shared volumes.
```bash
docker run -it dAngr -v <loal-binary-dir>:/home/ubuntu/dAngr/<binaryfile>
```

## Help
1. In the debugger prompt, you can find help as follows:
```bash
(dAngr)> help
```
## Documentation

Further documentation on the commands that may be used can be found [here](./docs/documentation.md).

## Example Usage

A basic example, demonstrating the capabilities of dAngr, can be found [here](./examples/basic_example/)

A more practical example, a simplified version of the vulnerability found in the Eufy ecosystem, can be found [here](./examples/aes_example/)

## Advanced Symobic Use Case
Without specifying any concrete inputs, dAngr will execute the target binary using symbolic inputs.  

## Contributing

Contributions to dAngr are welcome! If you find any bugs or have suggestions for new features, please open an issue or submit a pull request on GitHub.

## Research
Check out our other research [here](https://distrinet.cs.kuleuven.be/research/publications) 

## Citations
If you have used dAngr in your research, please cite at least the following paper describing it:
````{verbatim}
@inproceedings{dangr24, 
    author = {Goeman, V and de Ruck, D and Cordemans, T and Lapon, J and Naessens, V}, 
    booktitle = {Proceedings of the WOOT Conference on Offensive Technologies (WOOT '24)}, 
    month = {Aug}, 
    organization = {Philadelphia}, 
    title = {Reverse Engineering the Eufy Ecosystem: A Deep Dive into Security Vulnerabilities 
            and Proprietary Protocols},
    year = {2024},
    month = {Aug}, 
    conference = {USENIX WOOT Conference on Offensive Technologies}, 
}
````
## Contact
Have questions or feedback? Don't hesitate to reach out to us! Connect with our team on [GitHub Discussions](https://github.com/angr-debugging/dAngr/discussions), [open an issue](https://github.com/angr-debugging/dAngr/issues) on our repository or feel free to contact one of the authors.


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
