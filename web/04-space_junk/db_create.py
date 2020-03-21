#!/usr/bin/env python3

import MySQLdb

db = MySQLdb.connect(host='localhost', user='root',
                     passwd='toor')
cur = db.cursor()
root_queries = [
    "CREATE USER 'moderators_select'@'localhost' IDENTIFIED BY 'password';",
    "CREATE USER 'moderators_select'@'127.0.0.1' IDENTIFIED BY 'password';",
    "GRANT SELECT ON moderators.* TO 'moderators_select'@'localhost';",
    "GRANT SELECT ON moderators.* TO 'moderators_select'@'127.0.0.1';",
    "CREATE USER 'moderators_insert'@'localhost' IDENTIFIED BY 'password';",
    "GRANT INSERT ON moderators.* TO 'moderators_insert'@'localhost';",
    "GRANT CREATE ON moderators.* TO 'moderators_insert'@'localhost';",
]

for query in root_queries:
    cur.execute(query)

cur.close()
db.commit()
db.close()

# Connect to aliens database
db_moderators = MySQLdb.connect(host='localhost', user='moderators_insert',
                                passwd='password', db='moderators')
cur_moderators = db_moderators.cursor()

# Create moderators table
cur_moderators.execute(
    'CREATE TABLE moderators (id SMALLINT NOT NULL, username VARCHAR(32), password VARCHAR(32), session CHAR(4));')

moderators = {
    "Neil Armstrong": ["numero_uno", "000001"],
    "Buzz Aldrin": ["gemini12", "000002"],
    "John Glenn": ["threeforme1962", "009371"],
    "Sally Ride": ["Challenger1983", "002903"]
}

# Insert data into tables
for i, moderator in enumerate(moderators):
    cur_moderators.execute('INSERT INTO moderators (id, username, password, session) VALUES ("' + str(
        i) + '","' + moderator + '","' + moderators[moderator][0] + '","' + moderators[moderator][1] + '");')


# Commit changes
cur_moderators.close()
db_moderators.commit()
db_moderators.close()
