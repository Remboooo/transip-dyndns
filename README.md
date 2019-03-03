### TransIP dynamic DNS updater

## Installation
1. Create a virtualenv in a venv/ folder of this directory with Python 3
2. Install https://github.com/benkonrath/transip-api into this virtualenv
3. Follow the instructions for getting an API key from the above repo
4. Create a `transip_config.yml` based on `transip_config.yml.example`
5. Run `transip-dyndns -v` for verbose mode to see if everything is OK
6. (Optional) add to a crontab. Make sure to provide an absolute path to your `transip_config.yml` using the `-f` switch.
