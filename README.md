# Italian Telegraph Intercept (Networking / Dynamic Generator, Medium - 500 pts)

**Story:**
Before the battle of Adwa, the Italian expeditionary force under Baratieri relied on field telegraph lines connected to coastal headquarters at Massawa. Tigrayan scouts under Ras Alula Engida tapped into these copper wires near Sauria, intercepting operational orders before the Italian columns had even formed their battle ranks.

## Mechanics
- This challenge supports the platform's **On-Demand Dynamic File Generator** to generate personalized challenge files with participants' unique dynamic flags.
- Players receive two files in `output/`:
  - `output/intercept.pcap`: A valid network capture file containing Ethernet/IPv4/TCP frames transmitting the Italian Military Telegraph Protocol (`IMTP/1.0`) on port 1896.
  - `output/wiretap_log.txt`: Tactical intelligence report documenting the Sauria wiretap operation, protocol specs, and target endpoints.
- The traffic includes routine check-ins, column advance dispatches, and an encrypted telegram payload:
  `IMTP/1.0 ENCRYPTED_TELEGRAM WIRE_ID=... DATA=<BASE64>`
- Decoding the Base64 reveals the confidential telegram from Civil Commissioner Ferdinando Martini to General Baratieri warning of Ethiopian troop strength, along with the participant's flag.

## Dynamic File Generator Settings
- **Type**: `dynamic`
- **Output Filename**: `intercept.pcap`
- **Container Image**: `ghcr.io/azariyasmekonen/italian-telegraph-intercept:latest`
- **Environment Variables**:
  - `FLAG`: Dynamic participant flag (e.g. `AdwaCTF{...}`)
  - `USER_ID`: Unique participant or team identifier
  - `OUTPUT_DIR`: Target directory (defaults to `/output`)
  - `OUTPUT_FILENAME`: Name of output file inside `/output/` (defaults to `intercept.pcap`)

## Solution Walkthrough
1. Open `output/intercept.pcap` in Wireshark, tshark, or parse with Python.
2. Filter for TCP port 1896:
   ```bash
   tshark -r output/intercept.pcap -Y "tcp.port == 1896" -T fields -e tcp.payload
   ```
3. Locate the packet containing the telegram:
   `IMTP/1.0 ENCRYPTED_TELEGRAM WIRE_ID=... DATA=...`
4. Extract the base64 string from `DATA=` and decode it.
5. Recover the flag: `AdwaCTF{73l36r4ph_w1r35_t4pp3d_47_54ur14}`.

Run `solve/solve.py` to solve automatically.
