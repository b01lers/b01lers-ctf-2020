#!/usr/bin/env python3

from flask import Flask, render_template, request, send_file


app = Flask(__name__)


methods = ['GET', 'OPTIONS', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']


@app.route('/', methods=methods)
def index():
    if request.method in methods[5:len(methods)] or request.method == 'GET':
        return render_template('cant.html', err='Cant ' + request.method + ' /')
    return render_template('index.html')


@app.route('/circle/one/', methods=methods)
def circle_one():
    if request.method != 'OPTIONS':
        return render_template('cant.html', err='Cant ' + request.method + ' /circle/one/')
    return send_file('./static/msuspcsbs_hein_hjheinzcom38.pdf')


@app.route('/two/', methods=methods)
def two():
    if request.method != 'PUT' and request.method != 'CONNECT':
        return render_template('cant.html', err='Cant ' + request.method + ' /two/')
    if request.method == 'PUT':
        return 'Put the dots???'
    return send_file('./static/doots.png')


@app.route('/square/', methods=methods)
def square():
    if request.method != 'DELETE':
        return render_template('cant.html', err='Cant ' + request.method + ' /square/')
    return send_file('./static/crozz.png')


@app.route('/com/seaerch/', methods=methods)
def com_seaerch():
    if request.method != 'GET':
        return render_template('cant.html', err='Cant ' + request.method + ' /com/seaerch/')
    form_dict = request.form.to_dict()

    if 'search' in form_dict:
        return render_template('seaerch.html', search=form_dict['search'])
    return render_template('seaerch.html')


@app.route('/vim/quit/', methods=methods)
def vim_quit():
    if request.method != 'TRACE':
        return render_template('cant.html', err='Cant ' + request.method + ' /vim/quit/')
    exit = None
    try:
        # No exit querystring
        exit = request.args.get('exit').strip()
    except:
        pass
    return render_template('quit.html', exit=exit)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
