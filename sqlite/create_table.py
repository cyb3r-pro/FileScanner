#!usr/bin/env python
# -*- coding: utf-8 -*-

import sqlite3
import sys

conn = None

# Name of the sqlite database file
db = "filescanner.sqlite"    	

# SQL Datatypes
# SQL timestamp DATETIME2
# SQL filename NVARCHAR(100)
# SQL tool VARCHAR(20)
# SQL tool_result NVARCHAR(200)

try:
	# Connecting to the database file
	conn = sqlite3.connect(db)
	c = conn.cursor()
	
	# Creating a fs_summary SQLite table
	c.execute("CREATE TABLE fs_summary ("
				"incident TEXT, " 
				"timestamp INTEGER NOT NULL, "
				"md5 TEXT NOT NULL, "
				"tool TEXT NOT NULL, " 
				"tool_result TEXT NOT NULL, " 
				"risk_level TEXT NOT NULL, " 				
				"indicators TEXT, " 				
				"last_scanned INTEGER NOT NULL, " 				
				"PRIMARY KEY (md5, tool_result))")

	# Creating a fs_filenames SQLite table
	c.execute("CREATE TABLE fs_filenames ("
				"timestamp INTEGER NOT NULL, " 
				"md5 TEXT NOT NULL, "					
				"filename TEXT NOT NULL, "			
				"PRIMARY KEY (md5, filename))")
				
	# Committing changes and closing the connection to the database file
	conn.commit()

except sqlite3.Error as e:
	if conn:
		conn.rollback()
	print("Error %s:" % e.args[0])		
	sys.exit(1)	

finally:
	if conn:
		conn.close()

