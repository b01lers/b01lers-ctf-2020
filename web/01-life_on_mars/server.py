#!/usr/bin/env python3

from flask import Flask, render_template, request, jsonify
import MySQLdb


app = Flask(__name__)


@app.route('/query')
def query():
    search = request.args.get('search')
    db = MySQLdb.connect(host='localhost', user='table_user', passwd='pass', db='aliens')
    cur = db.cursor()
    print('QUERY: ', 'SELECT name, description FROM ' + search)
    try:
        cur.execute("SELECT name, description FROM " + search)
        results = cur.fetchall()
        cur.close()
        db.close()
        return jsonify(results)

    except MySQLdb.ProgrammingError:
        return jsonify(1)

    except MySQLdb.OperationalError:
        return jsonify(2)


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
