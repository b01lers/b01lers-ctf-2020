#!/usr/bin/env python3
# To get the youtube playlist files:

import MySQLdb
import random
import pickle
import sys

db = MySQLdb.connect(host='localhost', user='root',
                     passwd='toor')
cur = db.cursor()
root_queries = [
    "CREATE DATABASE alien_code",
    "CREATE USER 'table_user'@'localhost' IDENTIFIED BY 'password';",
    "GRANT SELECT ON alien_code.* TO 'table_user'@'localhost';",
    "GRANT SELECT ON aliens.* TO 'table_user'@'localhost';",
    "CREATE USER 'table_insert'@'localhost' IDENTIFIED BY 'password';",
    "GRANT INSERT ON aliens.* TO 'table_insert'@'localhost';",
    "GRANT INSERT ON alien_code.* TO 'table_insert'@'localhost';",
    "GRANT CREATE ON aliens.* TO 'table_insert'@'localhost';",
    "GRANT CREATE ON alien_code.* TO 'table_insert'@'localhost';",
    ]

for query in root_queries:
    cur.execute(query)

cur.close()
db.commit()
db.close()

# Connect to aliens database
db_aliens = MySQLdb.connect(host='localhost', user='table_insert',
                            passwd='password', db='aliens')
cur_aliens = db_aliens.cursor()

# Create alien locations table
locations = ['amazonis_planitia', 'olympus_mons', 'tharsis_rise', 'chryse_planitia',
    'arabia_terra', 'noachis_terra', 'hellas_basin', 'utopia_basin', 'hesperia_planum']

for each in locations:
    cur_aliens.execute('CREATE TABLE ' + each +
                       ' (id SMALLINT NOT NULL, name VARCHAR(1000), description VARCHAR(1000));')

# location of file
cwd = sys.argv[0]
cwd = cwd[1: 1 + cwd.rfind('/')]

# Load names
aliens = []
with open(cwd + 'data/alien_names.pkl', 'rb') as fd_aliens:
    aliens = pickle.load(fd_aliens)

# Load descriptions
descriptions = []
with open(cwd + 'data/alien_descriptions.pkl', 'rb') as fd_aliens:
    descriptions = pickle.load(fd_aliens)

# Insert data into tables
for i, name in enumerate(aliens):
    # 23 is 'Alien Sex Goddess', don't put that in there (thanks wikipedia)
    if i == 23:
        continue

    rand = random.randint(0, 15)
    if rand < len(locations):
        # Insert into locations[rand] table
        try:
            cur_aliens.execute('INSERT INTO ' + locations[rand] + ' (id, name, description) VALUES ("' + str(i) + '","' + name + '","' + descriptions[i].replace('"', '') + '");')

        except UnicodeEncodeError:
            continue

        except IndexError:
            cur_aliens.execute('INSERT INTO ' + locations[rand] + ' (id, name, description) VALUES ("' + str(i) + '","' + name + '","");')


# Commit changes
cur_aliens.close()
db_aliens.commit()
db_aliens.close()


# Connect to alien_code table
db_code = MySQLdb.connect(host='localhost', user='table_insert',
                        passwd='password', db='alien_code')
cur_code = db_code.cursor()

# Create table
cur_code.execute(
    'CREATE TABLE code (id SMALLINT NOT NULL, code VARCHAR(1000));')

# Insert flag into table
cur_code.execute('INSERT INTO code (id, code) VALUES("0", "pctf{no_intelligent_life_here}");')


# Commit changes
cur_code.close()
db_code.commit()
db_code.close()
