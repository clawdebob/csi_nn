import json, zlib
from base64 import b64encode
import subprocess
import numpy as np
from nexcsi import decoder
from datetime import datetime

DEVICE = "raspberrypi"
CHANNEL = 56
BANDWIDTH = 40
TIMESTAMPS_NUM = 150
MQQT_BROKER_ADDRESS = '<Your processing server address>'

scan_air = ["tcpdump", "-i", "wlan0", "dst port 5500", "-vv", "-w", "output.pcap", "-c", str(TIMESTAMPS_NUM)]
def read_pcap_from(path):
    samples_r = decoder(DEVICE).read_pcap(path, bandwidth=BANDWIDTH)

    return decoder(DEVICE).unpack(samples_r['csi'], zero_nulls=False)
def run_scan_air():
    start = datetime.now()
    start_time = start.strftime("%d/%m/%Y %H:%M:%S")
    subprocess.run(scan_air)
    end = datetime.now()
    end_time = end.strftime("%d/%m/%Y %H:%M:%S")
    csi = read_pcap_from('../test/output.pcap')
    csi = np.delete(csi, csi.dtype.metadata['nulls'] + csi.dtype.metadata['pilots'], axis=1)
    csi = np.abs(csi)
    first_part = {}

    for i in range(TIMESTAMPS_NUM):
        first_part[str(i)] = list(map(lambda x: str(x), csi[i]))

    zipped_data = b64encode(zlib.compress(json.dumps(first_part).encode('utf-8'))).decode('ascii')

    msg = json.dumps({
        'device': DEVICE,
        'start': start_time,
        'end': end_time,
        'activity': 'to_process:' + zipped_data
    })

    publish = [
        "mosquitto_pub",
        "-h",
        "localhost",
        "-t",
        "/scan",
        "-m",
        msg,
    ]

    subprocess.run(publish)

    return

while True:
    run_scan_air()

