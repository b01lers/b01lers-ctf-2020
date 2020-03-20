#!/usr/bin/env python3

from flask import Flask, render_template


app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/die/')
def die():
    return render_template('die.html')


@app.route('/chase/')
def chase():
    return render_template('chase.html')


@app.route('/leftt/')
def leftt():
    return render_template('leftt.html')


@app.route('/shoot/')
def shoot():
    return render_template('shoot.html')


@app.route('/door/')
def door():
    return render_template('door.html')


@app.route('/open/')
def open():
    return render_template('open.html')


@app.route('/fight/')
def fight():
    return render_template('fight.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
