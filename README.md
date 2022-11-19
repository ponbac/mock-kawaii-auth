# Installation

## Run with Docker

To run the API with Docker, simply start with `docker compose`.

```
docker compose up
```

Then you should be able to launch the Kawaii React frontend and login with:

```
username: johndoe
password: secret
```

Since the `/src` directory is mounted in the container and the API is using the `uvicorn --watch` flag, you can edit the code in `main.py` and see the changes immediately.

## Running without Docker (use vscode)

### 1. If you dont already have it, install Python with version >= 3.10.

### 2. Install PDM:

### Windows (PowerShell)

```
(Invoke-WebRequest -Uri https://raw.githubusercontent.com/pdm-project/pdm/main/install-pdm.py -UseBasicParsing).Content | python -
```

### MacOS/Linux

```
curl -sSL https://raw.githubusercontent.com/pdm-project/pdm/main/install-pdm.py | python3 -
```

### 3. Install the vscode PDM extension:

```
pdm plugin add pdm-vscode
```

### 4. Install dependencies (should maybe be run in reverse order):

If promted about virtualenv, say no and use PEP582.

```
pdm use
pdm install
```

### 5. Run the API:

Press `F5` in vscode to run the API or execute manually:

```
pdm start
```

### 6. Login

Then you should be able to launch the Kawaii React frontend and login with:

```
username: johndoe
password: secret
```

# Swagger URL

## http://localhost:44344/docs
