import pandas as pd

data_path_1 = r'firewall-blocked-5-to-0-days-ago.csv'
data_path_2 = r'firewall-blocked-10-to-5-days-ago.csv'
data_path_3 = r'firewall-blocked-15-to-10-days-ago.csv'

# Specify column names
columns = ['timestamp', 'id', 'message', 'uptime']

# Create dataframes for each csv file
data_raw_1 = pd.read_csv(data_path_1, names = columns, header = 0)
data_raw_2 = pd.read_csv(data_path_2, names = columns, header = 0)
data_raw_3 = pd.read_csv(data_path_3, names = columns, header = 0)

# Merge dataframes
data_raw = data_raw_1.append(data_raw_2).append(data_raw_3, ignore_index = True)

# Drop duplicate rows
data_raw = data_raw.drop_duplicates().reset_index(drop = True)

# Create a copy of the data to be modified
data = data_raw.copy()

# Define a positive integer generator for the id generation function
def gen_n():
    n = 0
    while True:
        n += 1
        yield n

nat_num = gen_n()

# Generate a new id for any log with '#NAME?' or '#REF!' as current id value
data.loc[data['id'].isin(['#REF!', '#NAME?']), 'id'] = data[
    data['id'].isin(['#REF!', '#NAME?'])]['id'].apply(lambda x: 'new_id_' + str(next(nat_num)))

def ufw_to_dict(block):
    
    # Split the string into a list of strings with space as a delimiter
    temp_list_1 = block.split(' ')
    # Split the new strings with '=' as a delimiter, then remove the lists with only 1 entry
    temp_list_2 = [temp_list_1[i].split('=') for i in range(len(temp_list_1)) if len(temp_list_1[i].split('=')) > 1]
    # Convert the list of lists into a dictionary
    ufw_dict = {temp_list_2[i][0] : temp_list_2[i][1] for i in range(len(temp_list_2))}
    
    return ufw_dict

# Create a (temporary) column consisting of the newly obtained dictionaries
data['message_dict'] = data['message'].apply(ufw_to_dict)

# Obtain the MAC address of the attacked machines
data['mac'] = data['message_dict'].apply(lambda x: x['MAC'])

# Obtain the IP address of the attacking machines
data['src'] = data['message_dict'].apply(lambda x: x['SRC'])

# Obtain the protocols
data['proto'] = data['message_dict'].apply(lambda x: x['PROTO'])

# Obtain the destination ports
data['dpt'] = data[data['proto'].isin(['TCP', 'UDP'])]['message_dict'].apply(lambda x: x['DPT'])

import geoip2.database

# Create an IP geolocation database reader
reader = geoip2.database.Reader('GeoLite2-Country.mmdb')

# Create a column containing ISO codes of the respective countries
data['country'] = data['src'].apply(lambda x: reader.country(x).country.iso_code)

# Drop unnecessary columns
data = data.drop(columns = ['message_dict', 'message'])

# Drop columns irrelevant to the current task
data = data.drop(columns = ['uptime', 'proto', 'dpt', 'src'])

import datetime as dt

# Convert to datetime object
data['timestamp'] = data['timestamp'].apply(lambda x: dt.datetime.strptime(x[:-4].replace(',', ''), '%Y/%m/%d %H:%M:%S'))

# Strip the seconds
data['timestamp'] = data['timestamp'].dt.floor('Min')

# Define a function to assign each MAC a name
def assign_name(mac):
    
    if mac == 'ca:2f:ec:b2:3d:de:fe:00:00:00:01:01:08:00':
        return 'Joey'
    elif mac == 'ca:df:f0:4b:1d:32:fe:00:00:00:01:01:08:00':
        return 'Mai'
    elif mac == '1a:2f:06:b9:bc:25:fe:00:00:00:01:01:08:00':
        return 'Shrek'
    elif mac == '92:df:d9:9c:c6:66:fe:00:00:00:01:01:08:00':
        return 'Maria'
    elif mac == '96:d4:b3:c3:53:46:fe:00:00:00:01:01:08:00':
        return 'Leonardo'
    elif mac == '4a:ca:d7:24:d9:00:fe:00:00:00:01:01:08:00':
        return 'Donatelo'
    elif mac == '36:65:39:a3:00:84:fe:00:00:00:01:01:08:00':
        return 'Michael'
    elif mac == 'da:cc:23:d6:96:04:fe:00:00:00:01:01:08:00':
        return 'Christiano'
    elif mac == '1a:f4:00:ba:fa:c9:fe:00:00:00:01:01:08:00':
        return 'Shakira'
    elif mac == 'ee:cb:e2:91:c8:3c:fe:00:00:00:01:01:08:00':
        return 'Ivan'
    else:
        return 'Peter'

# Apply function to the data
data['computer_name'] = data['mac'].apply(assign_name)

from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient('mongodb+srv://user-1:password-1@cluster0.75fuz.mongodb.net/test')

# Get database
db = client.get_database('firewall_system_logs')

# Get collection
records = db.firewall_system_logs

# Delete the old data from the collection
records.delete_many({})

# Insert the data into the collection in json format
records.insert_many(data.to_dict('records'))

# Export data in a csv fromat
data.to_csv(r'firewall-blocked-clean.csv')