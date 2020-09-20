# Lorenzini

Lorenzini is the JSON parser to make packet analyzing by Wireshark more easier.
You can get packet informations as you want, and analyze them by Google Spreadsheet or Microsoft Office Excel.

# Functions

- Link HTTP request and response by frame number.
- Select information as you like, each packet type.
    - frame
    - HTTP
        - request
        - response

# How to use

- Capture packets by Wireshark
- Export packets as JSON([File] -> [Export Packet Dissections] -> [As JSON])
- Edit require_infos.yml to specify informations as you want.
- Execute Lorenzini, with the JSON file as input.
- You get XSV(such as CSV, TSV, Pipe-SV, as you like), please copy and paste to spreadsheet-like tools.

```
./lorenzini.py [JSON file name] [delimiter(default is ",")]
```

