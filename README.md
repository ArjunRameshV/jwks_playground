# Intorduction to Json Web Keys (JWK)

* A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key
* The technical specifications can be found in [RFC-7517](https://datatracker.ietf.org/doc/html/rfc7517)


## How to use this Repo

### Setup the repo

* The repo uses Pipfile to create a python venv and also has necessary packages required as part of the Pipfile.
* To enter the vitual env, use `pipenv shell`
* To install the packages once inside, use `pipenv install`

### Generate RSA keys
* We will be generating some RSA keys which can be used to sign the JWT.
* You can generate the keys using `python generate_certs.py --num_keys 3`, the number argument let's you create "n" different keys 

### Running the server
* Once the keys are generated, we can spin up the server using `python server.py`
* We can call the jwks endpoint using `curl http://localhost:5050/jwks-endpoint | python -m json.tool` 

### Using the client
* Once the server is up and running, we can use the client script to connect to the server, receive a JWT Token, get the JWKS and decode the token
* The client can be run using `python client.py --key_id 1`, where the `key_id` argument indicates the key we'll be attempting to use.
* The client expects the server to encode the the key id as part of the JWT token header and performs a match againt the header from the unverified JWT token and available keys from JWKS 