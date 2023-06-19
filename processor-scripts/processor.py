import paho.mqtt.subscribe as subscribe
import subprocess
import json
import zlib
import numpy as np
from base64 import b64decode
import pandas as pd
from skimage.restoration import denoise_wavelet
from keras.models import load_model

model = load_model('./lstm_o.keras')
ACC_VECTOR = ["walk", "jump", "wave", "empty"]
SECURITY_TOKEN = "Gu8CXZYtpy4z1Ya1818T"
THINGSBOARD_SERVER_ADDRESS = "localhost" # enter your server address

def median_absolute_deviation(x):
    """
    Returns the median absolute deviation from the window's median
    :param x: Values in the window
    :return: MAD
    """
    return np.median(np.abs(x - np.median(x)))

def hampel_d(ts, window_size=5, n=3, imputation=False):

    """
    Median absolute deviation (MAD) outlier in Time Series
    :param ts: a pandas Series object representing the timeseries
    :param window_size: total window size will be computed as 2*window_size + 1
    :param n: threshold, default is 3 (Pearson's rule)
    :param imputation: If set to False, then the algorithm will be used for outlier detection.
        If set to True, then the algorithm will also imput the outliers with the rolling median.
    :return: Returns the outlier indices if imputation=False and the corrected timeseries if imputation=True
    """

    if type(ts) != pd.Series:
        raise ValueError("Timeserie object must be of tyme pandas.Series.")

    if type(window_size) != int:
        raise ValueError("Window size must be of type integer.")
    else:
        if window_size <= 0:
            raise ValueError("Window size must be more than 0.")

    if type(n) != int:
        raise ValueError("Window size must be of type integer.")
    else:
        if n < 0:
            raise ValueError("Window size must be equal or more than 0.")

    # Copy the Series object. This will be the cleaned timeserie
    ts_cleaned = ts.copy()

    # Constant scale factor, which depends on the distribution
    # In this case, we assume normal distribution
    k = 1.4826

    rolling_ts = ts_cleaned.rolling(window_size*2, center=True)
    rolling_median = rolling_ts.median().fillna(method='bfill').fillna(method='ffill')
    rolling_sigma = k*(rolling_ts.apply(median_absolute_deviation).fillna(method='bfill').fillna(method='ffill'))

    outlier_indices = list(
        np.array(np.where(np.abs(ts_cleaned - rolling_median) >= (n * rolling_sigma))).flatten())

    if imputation:
        ts_cleaned[outlier_indices] = rolling_median[outlier_indices]
        return ts_cleaned

    return outlier_indices

def proccess_csi(csi):
  csi = np.array(csi, dtype=np.float32)

  for i in range(len(csi)):
    csi[i] = list(hampel_d(pd.Series(csi[i]), 3, imputation=True))

  csi = denoise_wavelet(csi, wavelet='sym6', mode='soft', wavelet_levels=3, method='BayesShrink', rescale_sigma='True')

  return csi

start_server = ["mosquitto", "-c", "/etc/mosquitto/mosquitto.conf"]

subprocess.run(start_server)

def proccess_packet(client, userdata, message):
    act = json.loads(message.payload)['activity']
    matrix = list(json.loads(zlib.decompress(b64decode(act.split('to_process:')[1]))).values())
    matrix = [[float(ele) for ele in sub] for sub in matrix]
    matrix = proccess_csi(matrix)
    matrix = np.reshape(matrix, (1, 150, 108))

    prediction_vec = model.predict([matrix])[0]
    ac_idx = np.argmax(prediction_vec)
    accuracy = prediction_vec[ac_idx]

    f = open("processor-scripts/db.json", "r")
    countData = json.loads(f.read())
    countData['c_' + ACC_VECTOR[ac_idx]] = countData['c_' + ACC_VECTOR[ac_idx]] + 1
    f.close()

    f = open("processor-scripts/db.json", "w")
    f.write(json.dumps(countData))
    f.close()

    data = {
        **countData,
        **message.payload,
        'activity': ac_idx,
        'accuracy': accuracy
    }

    msg = json.dumps(data)

    publish = [
        "mosquitto_pub",
        "-d",
        "-q",
        "1",
        "-h",
        THINGSBOARD_SERVER_ADDRESS,
        "-p",
        "1883",
        "-t",
        "v1/devices/me/telemetry",
        "-u",
        SECURITY_TOKEN,
        "-m",
        msg
    ]

    subprocess.run(publish)

subscribe.callback(proccess_packet, "/scan", hostname="localhost")