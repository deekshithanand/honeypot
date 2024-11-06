# SAMPLE HONEYPOT DEMO

## Instructions
Clone the project:

Pipenv is needed to setup the environment.
Install pipenv:
`pip install pipenv`

Install the project:
`pipenv install  #inside the project folder`

Run the application:
`python ./honeypot.py`

Open another terminal and hit the following ssh commands to hit the honey pot:

`ssh -o StrictHostKeyChecking=no -p 2222 localhost "exit" -o PreferredAuthentications=none`

If prompted for password , provide `passwd` as the password

If an error is Observerd try removing the host from known_hosts

`rm -rf ~/.ssh/known_hosts`

Experiment with various options in the menu

Simulations:
Blocks all manually provided IP address
blocks malicious IP (if connection count is more than 2)
Block all incomming SSH connections




