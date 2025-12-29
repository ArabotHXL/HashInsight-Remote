name: build

on:
  workflow_dispatch:
  push:
    branches: [ "main" ]

jobs:
  build:
    runs-on: windows-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        shell: pwsh
        run: |
          python -m pip install --upgrade pip
          python -m pip install -r requirements.txt
          python -m pip install -r requirements-build.txt
          python -c "import fastapi, uvicorn; print('Python deps OK')"

      - name: Build EXE (PyInstaller)
        shell: pwsh
        run: |
          pyinstaller --clean --noconfirm PickaxeCollector.spec

      - name: Verify dist output
        shell: pwsh
        run: |
          if (!(Test-Path dist/PickaxeCollector/PickaxeCollector.exe)) { throw "PickaxeCollector.exe not found under dist/PickaxeCollector/" }
          Get-ChildItem dist/PickaxeCollector | Select-Object Name,Length

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: PickaxeCollector-windows
          path: dist/PickaxeCollector
