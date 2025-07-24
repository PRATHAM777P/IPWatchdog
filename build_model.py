import pandas as pd
import os
import sys
import logging

logging.basicConfig(filename='ipwatchdog.log', level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

if not os.path.exists('ip_set.csv'):
    logging.error('ip_set.csv not found. Run dataset_generator.py first.')
    print('Error: ip_set.csv not found. Run dataset_generator.py first.')
    sys.exit(1)

try:
    dataset = pd.read_csv('ip_set.csv')
except Exception as e:
    logging.error(f'Error reading ip_set.csv: {e}')
    print(f'Error reading ip_set.csv: {e}')
    sys.exit(1)

if dataset.empty:
    logging.error('ip_set.csv is empty. No data to process.')
    print('Error: ip_set.csv is empty. No data to process.')
    sys.exit(1)

from sklearn.preprocessing import LabelEncoder
X = dataset.iloc[:,:]
x = X.to_numpy()

label = LabelEncoder()

try:
    IP = label.fit_transform(x[:,0])
    D = label.fit_transform(x[:,1])
    U = label.fit_transform(x[:,2])
except Exception as e:
    logging.error(f'Error encoding data: {e}')
    print(f'Error encoding data: {e}')
    sys.exit(1)

df1 = pd.DataFrame(IP, columns=['IPs'])
df2 = pd.DataFrame(D, columns=['DATE'])
df3 = pd.DataFrame(U, columns=['URL'])

frames = [df1, df2, df3]
result = pd.concat(frames, axis=1 )

from sklearn.preprocessing import StandardScaler
sc = StandardScaler()

data_scaled = sc.fit_transform(result)

from sklearn.cluster import KMeans

try:
    n_clusters = min(10, len(dataset)) if len(dataset) > 0 else 1
    model = KMeans(n_clusters=n_clusters)
    model.fit(data_scaled)
    pred  = model.fit_predict(data_scaled)
except Exception as e:
    logging.error(f'Error in KMeans clustering: {e}')
    print(f'Error in KMeans clustering: {e}')
    sys.exit(1)

dataset_scaled = pd.DataFrame(data_scaled, columns=['IP', 'Date', 'URL'])
dataset_scaled['cluster name'] = pred

ips = [dataset['IP'], result['IPs']]
ips_result = pd.concat(ips, axis=1)

def CountFrequency(my_list, ip_label):
    freq = {}
    for item in my_list:
        if (item in freq):
            freq[item] += 1
        else:
            freq[item] = 1
    max_freq = 0
    max_key = 0
    for key, value in freq.items():
        if value > max_freq:
            max_freq = value
            max_key = key
    return ip_label[my_list.index(max_key)] if my_list else 'No IP found'

res = CountFrequency(ips_result['IPs'].tolist(), ips_result['IP'].tolist())

try:
    with open('result.txt','w') as file1:
        file1.write(res)
    logging.info(f'Suspicious IP written to result.txt: {res}')
except Exception as e:
    logging.error(f'Error writing result.txt: {e}')
    print(f'Error writing result.txt: {e}')
    sys.exit(1)
