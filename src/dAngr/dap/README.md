# dap model creation:

## fetch jsonschme from web;

[specification](https://microsoft.github.io/debug-adapter-protocol/specification)
[download](https://microsoft.github.io/debug-adapter-protocol/debugAdapterProtocol.json)

```bash
wget https://microsoft.github.io/debug-adapter-protocol/debugAdapterProtocol.json -O debug_adapter_protocol.json
```

## create a model from jsonschema;

```bash
datamodel-codegen --input debug_adapter_protocol.json --input-file-type jsonschema --output dap_model.py
```