import pandas as pd
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
import numpy as np

csv_path = "/home/garlicbread/opcua/features.csv"
df = pd.read_csv(csv_path)

df.fillna({"src_ip": "0.0.0.0", "dst_ip": "0.0.0.0", "src_port": 0, "dst_port": 0, "opcua_payload": ""}, inplace=True)

ip_encoder = LabelEncoder()
df["src_ip"] = ip_encoder.fit_transform(df["src_ip"])
df["dst_ip"] = ip_encoder.fit_transform(df["dst_ip"])

df["src_port"] = df["src_port"].astype(int)
df["dst_port"] = df["dst_port"].astype(int)

scaler = MinMaxScaler()
df[["src_port", "dst_port"]] = scaler.fit_transform(df[["src_port", "dst_port"]])

def hex_to_int_array(hex_str, max_len=50):
    try:
        byte_array = bytes.fromhex(hex_str)  
        int_array = np.frombuffer(byte_array, dtype=np.uint8) 
        int_array = np.pad(int_array, (0, max_len - len(int_array)), 'constant')[:max_len]  
        return int_array
    except:
        return np.zeros(max_len)

df["opcua_payload"] = df["opcua_payload"].apply(lambda x: hex_to_int_array(x).tolist())

processed_csv_path = "opcua_preprocessed.csv"
df.to_csv(processed_csv_path, index=False)

print(f"Preprocessing complete. Data saved to {processed_csv_path}")
